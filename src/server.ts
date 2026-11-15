// Long-lived server entry: `npm run build && npm start`.
import { createHttpServer } from "./httpServer";

const port = Number(process.env.PORT ?? 3000);
const server = createHttpServer();

server.listen(port, () => {
  console.log(`0xrnld-proof-verifier listening on :${port}`);
});

const shutdown = () => server.close(() => process.exit(0));
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
