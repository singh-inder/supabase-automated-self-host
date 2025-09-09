import { randomUUID } from "node:crypto";
import { createClient, type RealtimeChannel } from "@supabase/supabase-js";
import { cleanEnv, str } from "envalid";
import wretch from "wretch";
import { test, describe, beforeAll, vi } from "vitest";
import { S3Client, ListBucketsCommand } from "@aws-sdk/client-s3";

beforeAll(() => {
  cleanEnv(process.env, {
    SUPABASE_PUBLIC_URL: str(),
    SERVICE_ROLE_KEY: str(),
    ANON_KEY: str(),
    REGION: str(),
    S3_PROTOCOL_ACCESS_KEY_ID: str(),
    S3_PROTOCOL_ACCESS_KEY_SECRET: str()
  });
});

const tableName = "todos";

const createCustomClient = (key: string) => {
  return createClient(process.env.SUPABASE_PUBLIC_URL!, key, {
    auth: { persistSession: false, autoRefreshToken: false }
  });
};

const getCredentials = () => ({
  email: `j-${randomUUID()}@mail.com`,
  password: "password123456"
});

const createBucketAndUpload = async (
  client: Client,
  bucket: string,
  filePath: string
) => {
  const blob = await wretch("https://placehold.co/400").get().blob();

  return await client.storage.from(bucket).upload(filePath, blob);
};

type Client = ReturnType<typeof createCustomClient>;

/** needs supabase instance created with SERVICE_ROLE_KEY */
const createVerifiedUser = (supabase: Client) => {
  return supabase.auth.admin.createUser({
    ...getCredentials(),
    email_confirm: true
  });
};

const createNote = async (supabase: Client, userId: string) => {
  const res = await supabase
    .from(tableName)
    .insert({
      task: "This is a test note",
      user_id: userId,
      is_complete: true
    })
    .select("id")
    .single();
  return res;
};

describe.concurrent("supabase test suite", () => {
  const SERVICE_ROLE_KEY = process.env.SERVICE_ROLE_KEY!;
  const ANON_KEY = process.env.ANON_KEY!;

  test("CRUD operations with verified user", async ({ expect }) => {
    const supabase = createCustomClient(SERVICE_ROLE_KEY);
    const authRes = await createVerifiedUser(supabase);

    expect(authRes.error).toBeNull();
    const user = authRes.data.user;

    const userId = user?.id;
    expect(userId).toBeTruthy();

    const createRes = await createNote(supabase, userId!);

    expect(createRes.error).toBeNull();

    const id: number | undefined = createRes.data?.id;
    expect(id).not.toBeNaN();

    const updateRes = await supabase
      .from(tableName)
      .update({ task: "This is an updated note" })
      .eq("id", id);

    expect(updateRes.error).toBeNull();

    const deleteRes = await supabase.from(tableName).delete().eq("id", id);
    expect(deleteRes.error).toBeNull();
  });

  test("Storage", async ({ expect }) => {
    const supabase = createCustomClient(SERVICE_ROLE_KEY);
    const authRes = await createVerifiedUser(supabase);

    expect(authRes.error).toBeNull();
    expect(authRes.data.user).not.toBeNull();

    const filePath = "test.jpg";
    // buckets are defined in todos.sql
    const bucket = "test-bucket";

    const upload = await createBucketAndUpload(supabase, bucket, filePath);
    expect(upload.error).toBeNull();

    const signedUrl = await supabase.storage
      .from(bucket)
      .createSignedUrl(filePath, 5 * 60);

    expect(signedUrl.error).toBeNull();

    [signedUrl.data, signedUrl.data?.signedUrl].forEach(v => expect(v).toBeTruthy());

    const removeRes = await supabase.storage.from(bucket).remove([filePath]);
    expect(removeRes.error).toBeNull();
  });

  test("Access buckets via s3 client", async ({ expect }) => {
    const supabase = createCustomClient(SERVICE_ROLE_KEY);
    const authRes = await createVerifiedUser(supabase);

    expect(authRes.error).toBeNull();
    expect(authRes.data.user).not.toBeNull();

    const filePath = `test${Math.floor(Math.random() * 100000)}.jpg`;
    const upload = await createBucketAndUpload(supabase, "another-bucket", filePath);
    expect(upload.error).toBeNull();

    const s3Client = new S3Client({
      endpoint: process.env.SUPABASE_PUBLIC_URL! + "/storage/v1/s3",
      forcePathStyle: true,
      region: process.env.REGION!,
      credentials: {
        accessKeyId: process.env.S3_PROTOCOL_ACCESS_KEY_ID!,
        secretAccessKey: process.env.S3_PROTOCOL_ACCESS_KEY_SECRET!
      }
    });

    expect(
      Array.isArray((await s3Client.send(new ListBucketsCommand())).Buckets)
    ).toBe(true);
  });

  test("Realtime db changes", { retry: 5 }, async ({ expect, onTestFinished }) => {
    const supabase = createCustomClient(SERVICE_ROLE_KEY);
    const authRes = await createVerifiedUser(supabase);

    expect(authRes.error).toBeNull();
    expect(authRes.data.user).not.toBeNull();

    const mockFn = vi.fn(payload => {});

    const channel = await new Promise<RealtimeChannel>(res => {
      const ch = supabase
        .channel("db-changes")
        .on("postgres_changes", { event: "INSERT", schema: "public" }, mockFn)
        .subscribe((_, err) => {
          expect(err).toBeFalsy();

          res(ch);
        });
    });

    onTestFinished(() => void channel.unsubscribe());

    const createRes = await createNote(supabase, authRes.data!.user!.id);
    expect(createRes.error).toBeNull();

    await vi.waitFor(() => expect(mockFn).toHaveBeenCalled(), {
      timeout: 4 * 1000
    });
  });

  test("Test functions", { retry: 2 }, async ({ expect }) => {
    const supabase = createCustomClient(ANON_KEY);

    const { error, data } = await supabase.functions.invoke("hello", {
      method: "GET"
    });

    expect(error).toBeNull();
    expect(data).toBe("Hello from Edge Functions!");
  });
});
