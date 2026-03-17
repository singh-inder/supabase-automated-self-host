import { randomUUID, hash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createClient, type RealtimeChannel } from "@supabase/supabase-js";
import { cleanEnv, str } from "envalid";
import wretch from "wretch";
import { test, describe, beforeAll, vi } from "vitest";
import { S3Client, ListBucketsCommand, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { Client } from "pg";

const getRandomCredentials = () => ({
  email: `j-${randomUUID()}@mail.com`,
  password: "password123456"
});

const userCredentials = getRandomCredentials();
const testImg = fs.readFileSync(
  path.resolve(import.meta.dirname, "testdata/sample.webp")
);

beforeAll(async () => {
  const PG_USER = "postgres";
  const { POSTGRES_PASSWORD, POSTGRES_DB, POOLER_TENANT_ID, POSTGRES_PORT } = cleanEnv(
    process.env,
    {
      SUPABASE_PUBLIC_URL: str(),
      SERVICE_ROLE_KEY: str(),
      POSTGRES_PASSWORD: str(),
      POSTGRES_DB: str(),
      POOLER_TENANT_ID: str(),
      POSTGRES_PORT: str()
    }
  );

  const db = await new Client(
    `postgres://${PG_USER}.${POOLER_TENANT_ID}:${POSTGRES_PASSWORD}@localhost:${POSTGRES_PORT}/${POSTGRES_DB}`
  ).connect();
  const sql = fs.readFileSync(path.resolve(import.meta.dirname, "./todos.sql"), {
    encoding: "utf-8"
  });
  await db.query(sql);
  await db.end();

  const { error } = await createVerifiedUser(
    createSupabaseClient(process.env.SERVICE_ROLE_KEY!),
    userCredentials
  );
  if (error) throw error;
});

const tableName = "todos",
  bucketName = "test-bucket";

const createSupabaseClient = (key: string) => {
  return createClient(process.env.SUPABASE_PUBLIC_URL!, key, {
    auth: { persistSession: false, autoRefreshToken: false }
  });
};

type SupabaseClient = ReturnType<typeof createSupabaseClient>;

/** needs supabase client created with SERVICE_ROLE_KEY */
const createVerifiedUser = (
  supabase: SupabaseClient,
  creds: ReturnType<typeof getRandomCredentials>
) => {
  return supabase.auth.admin.createUser({
    ...creds,
    email_confirm: true
  });
};

const createNote = async (supabase: SupabaseClient, userId: string) => {
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
  const { SERVICE_ROLE_KEY, ANON_KEY } = cleanEnv(process.env, {
    SUPABASE_PUBLIC_URL: str(),
    SERVICE_ROLE_KEY: str(),
    ANON_KEY: str(),
    REGION: str(),
    S3_PROTOCOL_ACCESS_KEY_ID: str(),
    S3_PROTOCOL_ACCESS_KEY_SECRET: str()
  });

  const getS3Client = () => {
    return new S3Client({
      endpoint: process.env.SUPABASE_PUBLIC_URL! + "/storage/v1/s3",
      forcePathStyle: true,
      region: process.env.REGION!,
      credentials: {
        accessKeyId: process.env.S3_PROTOCOL_ACCESS_KEY_ID!,
        secretAccessKey: process.env.S3_PROTOCOL_ACCESS_KEY_SECRET!
      }
    });
  };

  const allKeys = [
    [ANON_KEY, "anon_key"],
    [SERVICE_ROLE_KEY, "service_role_key"]
  ];

  const adminKeys = [[SERVICE_ROLE_KEY, "service_role_key"]];

  test.for(allKeys)(
    "CRUD operations with verified user - $1",
    async ([key], { expect }) => {
      const supabase = createSupabaseClient(key);
      const authRes = await supabase.auth.signInWithPassword(userCredentials);

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
    }
  );

  test.for(adminKeys)("Storage - $1", async ([key], { expect }) => {
    const supabase = createSupabaseClient(key);
    const authRes = await createVerifiedUser(supabase, getRandomCredentials());
    expect(authRes.error).toBeNull();

    const filePath = `${crypto.randomUUID()}.webp`;
    // buckets are defined in todos.sql

    const upload = await supabase.storage.from(bucketName).upload(filePath, testImg);
    expect(upload.error).toBeNull();

    const createSignedUrl = await supabase.storage
      .from(bucketName)
      .createSignedUrl(filePath, 5 * 60);

    expect(createSignedUrl.error).toBeNull();
    expect(createSignedUrl.data?.signedUrl).toBeTruthy();

    const buf = await (
      await wretch().get(createSignedUrl.data?.signedUrl).blob()
    ).arrayBuffer();
    expect(hash("sha256", testImg)).toEqual(hash("sha256", Buffer.from(buf)));

    const createUploadUrl = await supabase.storage
      .from(bucketName)
      .createSignedUploadUrl(`${crypto.randomUUID()}.webp`);
    expect(createUploadUrl.error).toBeNull();

    const res = await supabase.storage
      .from(bucketName)
      .uploadToSignedUrl(
        createUploadUrl.data!.path,
        createUploadUrl.data!.token,
        testImg
      );

    expect(res.error).toBeNull();

    const removeRes = await supabase.storage.from(bucketName).remove([filePath]);
    expect(removeRes.error).toBeNull();
  });

  test("List buckets via s3 client", async ({ expect }) => {
    const s3Client = getS3Client();
    const buckets = (await s3Client.send(new ListBucketsCommand())).Buckets;
    expect(buckets).toEqual(
      expect.arrayContaining([expect.objectContaining({ Name: bucketName })])
    );
  });

  test("Upload img via s3 client", async () => {
    await getS3Client().send(
      new PutObjectCommand({
        Bucket: bucketName,
        Key: `${crypto.randomUUID()}.webp`,
        Body: testImg,
        ContentType: "image/webp"
      })
    );
  });

  test("Upload via s3 client - signed url", async ({ expect }) => {
    const body = "lorem-ipsum";
    const id = `${crypto.randomUUID()}.txt`;
    const command = new PutObjectCommand({
      Bucket: bucketName,
      Key: id,
      ContentType: "text/plain"
    });
    const signedUrl = await getSignedUrl(getS3Client(), command, {
      expiresIn: 5 * 60
    });
    await wretch(signedUrl).headers({ "Content-Type": "text/plain" }).put(body).res();
    const supabase = createSupabaseClient(ANON_KEY);
    await supabase.auth.signInWithPassword(userCredentials);
    const { data } = await supabase.storage.from(bucketName).download(id);
    expect(await data?.text()).toEqual(body);
  });

  test.for(allKeys)(
    "Realtime db changes - $1",
    async ([key], { expect, onTestFinished }) => {
      const supabase = createSupabaseClient(key);
      const authRes = await createVerifiedUser(supabase, getRandomCredentials());

      expect(authRes.error).toBeNull();

      const mockFn = vi.fn(payload => {});

      const channel = supabase
        .channel("db-changes")
        .on("postgres_changes", { event: "INSERT", schema: "public" }, mockFn)
        .subscribe();

      onTestFinished(() => void channel.unsubscribe());

      const createRes = await createNote(supabase, authRes.data!.user!.id);
      expect(createRes.error).toBeNull();

      await vi.waitFor(() => expect(mockFn).toHaveBeenCalled(), {
        timeout: 4 * 1000
      });
    }
  );

  test.for(allKeys)("Test functions - $1", async ([key], { expect }) => {
    const supabase = createSupabaseClient(ANON_KEY);

    const { error, data } = await supabase.functions.invoke("hello", {
      method: "GET"
    });

    expect(error).toBeNull();
    expect(data).toBe("Hello from Edge Functions!");
  });
});
