import aiohttp
import requests
import aiofiles
import asyncio
import json
import os
import io
import datetime
from difflib import HtmlDiff
from typing import List
import htmlmin
from bs4 import BeautifulSoup
from github import Github, Repository, ContentFile


async def download(
    c: ContentFile.ContentFile, out: str, session: aiohttp.ClientSession
):
    try:
        async with session.get(c.download_url) as res:
            output_path = os.path.join(out, c.path)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            async with aiofiles.open(output_path, "wb") as f:
                try:
                    print(f"downloading {c.path} to {output_path}")
                    while content := await res.content.read(20 << 10):
                        await f.write(content)
                except Exception as err:
                    print(f"Error writing file {c.name}: {err}")
                else:
                    return output_path
    except Exception as err:
        raise Exception(f"Error downloading {c.name}: {err}")


def get_repo_files(
    repo: Repository.Repository,
    folder: str,
    repoFiles: List[ContentFile.ContentFile],
    recursive: bool,
):
    contents = repo.get_contents(folder)
    for c in contents:
        if c.download_url is None:
            if recursive:
                get_repo_files(repo, c.path, repoFiles, recursive)
            continue
        repoFiles.append(c)


async def main():
    discord_webhook_url = os.environ.get("DISCORD_WEBHOOK_URL")

    if discord_webhook_url is None:
        raise SystemExit(
            "Error: DISCORD_WEBHOOK_URL env var not present",
        )

    current_dir = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(current_dir, "remote")
    local_docker_dir = os.path.normpath(os.path.join(current_dir, "../docker"))

    g = Github()
    repo = g.get_repo("supabase/supabase")
    repoFiles: List[ContentFile.ContentFile] = []
    get_repo_files(repo, "docker", repoFiles, True)

    remote_files = []

    async with aiohttp.ClientSession() as session:
        skip = ["readme.md", ".gitignore"]
        try:
            async with asyncio.TaskGroup() as tg:
                for f in repoFiles:
                    if f.name.lower() in skip:
                        print(f"skip downloading {f.name}")
                    else:
                        remote_files.append(tg.create_task(download(f, out, session)))
        except* Exception as err:
            raise SystemExit(f"ERROR in download taskgroup: {err.exceptions}")

    remote_files = [
        os.path.normpath(remote_file.result()) for remote_file in remote_files
    ]

    extra_files: List[str] = []
    html_head, html_body = "", ""
    legends_table_html, legends_selector = "", "table[summary='Legends']"

    for remote_file_path in remote_files:
        local_file_path = os.path.join(
            local_docker_dir,
            # have to use os.sep when splitting https://stackoverflow.com/a/1945930/18954618 returns path as=> /dev/data.sql
            remote_file_path.split(f"docker{os.sep}", maxsplit=1).pop(),
        )

        if not os.path.isfile(local_file_path):
            extra_files.append(remote_file_path)
            continue

        with open(remote_file_path, "r") as remote_file:
            try:
                with open(local_file_path, "r") as local_file:
                    local_lines = local_file.read().splitlines()
                    remote_lines = remote_file.read().splitlines()

                    fileName = os.path.basename(local_file_path)

                    html_diff = HtmlDiff().make_file(
                        local_lines,
                        remote_lines,
                        fromdesc=f"{fileName} Local File",
                        todesc=f"{fileName} Remote File",
                        context=True,
                        numlines=10,
                    )
                    soup = BeautifulSoup(html_diff, "html.parser")

                    # fmt: off
                    if "no differences" in soup.select_one("body table tbody tr").get_text().lower():
                        continue
                    # fmt: on

                    if html_head == "":
                        html_head = soup.find("head").decode()

                    legends_table = soup.select_one(legends_selector)

                    if legends_table is not None:
                        if legends_table_html == "":
                            legends_table_html = legends_table.decode()
                        legends_table.decompose()

                    html_body += soup.find("body").decode_contents()
            except Exception as err:
                raise SystemExit(
                    f"Error generating diff for file {remote_file_path}: {err}"
                )

    if len(html_body) == 0:
        html_diff = "<html><body><h1>No changes!</h1></body></html>"
    else:
        html_diff = f"""
        <html>
        {html_head}
        <body>
        {"" if len(extra_files) == 0 else f"<h1>extraFiles={str(extra_files)}</h1><br>"}
        {html_body}
        {legends_table_html}
        </body>
        </html>
        """

    report_date = datetime.datetime.now().strftime("%d-%m-%Y")

    file = io.StringIO(htmlmin.minify(html_diff, remove_empty_space=True))
    file.name = f"diff-{report_date}.html"

    try:
        res = requests.post(
            discord_webhook_url,
            data={
                "payload_json": json.dumps(
                    {"embeds": [{"title": f"Report {report_date}"}]}
                )
            },
            files={"file": file},
        )
        res.raise_for_status()
    except Exception as err:
        raise SystemExit(f"ERROR sending to discord webhook: {err}")
    finally:
        file.close()


if __name__ == "__main__":
    asyncio.run(main())
