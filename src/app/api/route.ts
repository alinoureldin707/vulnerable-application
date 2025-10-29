import { neon } from "@neondatabase/serverless";

export async function GET(request: Request) {
  // For example, fetch data from your DB here
  const sql = neon(process.env.DATABASE_URL!);
  //    create users table if not exists
  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `;

  await sql`INSERT INTO users (name, email, password) VALUES ('Ali Noureldin', 'alin@example.com', '123456') ON CONFLICT (email) DO NOTHING`;

  // For example, fetch data from your DB here
  const users = await sql`SELECT * FROM users`;
  return new Response(JSON.stringify(users), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
