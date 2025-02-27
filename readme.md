# Supabase automated self host

Deploy a self-hosted Supabase instance with 2-factor authentication (2FA) using [Authelia](https://github.com/authelia/authelia) and [Caddy](https://github.com/caddyserver/caddy) as a reverse proxy, all with **ONE bash script!**

👉 If you find this project helpful, please consider leaving a ⭐ to show your support. You can also support my work by [buying me a coffee](https://buymeacoffee.com/_inder1). Thankyou!

## Prerequisites

- **A Linux Machine with docker installed**: This can be a server or any personal computer running Linux with at least 1 GB RAM and 25 GB Disk space. **The script has been tested only on Linux/WSL.**

- **Own Domain**: Only required if you're going to expose supabase services to the internet. Otherwise you can run supabase locally (more on this in setup instructions)

## Setup Instructions

If you prefer a visual guide, check out this video where I deploy a self hosted supabase instance with Authelia for 2FA to AWS in a few minutes:

[![Self-Host Supabase with 2FA and Caddy](https://imgur.com/mCM0ZRG.jpeg)](https://www.youtube.com/watch?v=XhTBCGb0rTM "Self-Host Supabase with 2FA and Caddy - Just Run One Script!")

1. Download `setup.sh` script

   ```bash
    curl -o setup.sh https://raw.githubusercontent.com/singh-inder/supabase-automated-self-host/refs/heads/main/setup.sh
   ```

2. Make script executable

   ```bash
    chmod +x setup.sh
   ```

3. Execute script

   👉 If you only want basic username and password authentication

   ```bash
   sudo ./setup.sh
   ```

   👉 If you want 2-factor authentication setup with authelia

   ```bash
   sudo ./setup.sh --with-authelia
   ```

   During script execution, you'll be prompted to enter some details:

   - **Enter your domain:** Enter the domain name you want to access the supabase dashboard on. This is the host caddy server will listen for. Make sure to specify the `http/https` protocol.
     For example: `https://supabase.example.com`

     ⭐ If you only want to access the dashboard locally, refer to this [Guide](https://github.com/singh-inder/supabase-automated-self-host/discussions/6)

   - **Enter username:** Enter the username you want to use for authentication.

   - **Enter password:** Set a secure password.

   - **Do you want to send confirmation emails to register users? `[y/n]`:**

     - If you enter "yes", Supabase will send a verification email to every new user who registers. You'll need to set up your own SMTP server and enter the config in `.env` file. You can read more about it [here](https://supabase.com/docs/guides/self-hosting/docker#configuring-an-email-server).

     - If you enter "no", users will be able to signup with their email & password without any email verification. If you're only testing things out or don't want to send any verification/password-reset emails, enter "no"

   The following additional prompts have to be answered only if you've enabled `--with-authelia` flag:

   - **Enter email:** This email is used by authelia for setting up 2-factor auth / reset password flow. If you're not going to setup an SMTP server for emails, you can enter any email here. (When not using SMTP server, you can easily view codes sent by authelia in `docker/volumes/authelia/notifications.txt`)

   - **Enter Display Name:** Used by authelia in emails and [dashboard](https://gist.github.com/user-attachments/assets/a7a4c0b8-920e-4b61-9bb5-1cae26d5bbe9).

   - **Do you want to setup redis with authelia? [y/n]:** By default, authelia stores session data in memory. In layman terms: If authelia container dies for some reason every user will be logged out. **If you're going to production, Authelia team [recommends](https://www.authelia.com/configuration/session/redis/) to use redis to store session data**.

Thats it!

After script completes successfully, cd into `supabase/docker` directory and run `docker compose up -d`. Wait for containers to be healthy and you're good to go. To access dashboard outside your network, make sure that your firewall allows traffic on port 80 and 443.

## Rate limits

By default, Supabase api routes don't have any rate-limits on the self hosted instance. You can easily rate-limit api routes using caddy server by following the steps [HERE](https://github.com/singh-inder/supabase-automated-self-host/discussions/19)

## How this differs from coolify:

- Coolify needs at least 2 GB RAM and 30 GB of disk space. Supabase itself only needs 1 GB ram and 25 GB disk space to start.

- With coolify, you're only getting basic username password auth. No 2FA.

- Coolify relies on Kong API Gateway by default, without a separate reverse proxy. This project configures Caddy as a reverse proxy, allowing easy rate-limiting. Support for multiple reverse proxies is also planned.

- This script is definitely going to be faster than setting up through Coolify.

## Where to ask for help?

- Open a new issue
- [X/Twitter](https://x.com/_inder1)
- or stop by my [Discord server](https://discord.gg/Pbpm7NsVjG) anytime.

## License

This project is licensed under the [Apache 2.0 License](LICENSE).

Note: This project isn't officially supported by Supabase. For any information regarding Supabase itself you can refer to their [docs](https://supabase.com/docs).

## Contributions

Feel free to open issues or submit pull requests if you have suggestions or improvements.
