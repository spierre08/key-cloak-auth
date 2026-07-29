import { app } from "./app.js";
import { ConnectDb } from "./config/db.config.js";
import { EnvConfig } from "./config/env.config.js";

try {
  await ConnectDb();
  app.listen(EnvConfig.port, () =>
    console.log(`Serveur connecté sur le --${EnvConfig.port}`),
  );
} catch (error) {
  console.log(error.message);
}
