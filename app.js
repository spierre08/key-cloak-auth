import express from "express";
import cors from "cors";
import helmet from "helmet";

import { EnvConfig } from "./config/env.config.js";
import { MorganMiddleware } from "./middlewares/logging.middleware.js";
import { createRoles } from "./scripts/init-keycloak-roles.js";
import { getKey } from "./scripts/get-key.js";

import { AuthRoutes } from "./routes/auth.routes.js";

export const app = express();

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(helmet());
app.use(
  cors({
    origin: [""],
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(MorganMiddleware);

app.use(`${EnvConfig.apiPrefix}/auth`, AuthRoutes);

app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

app.use(async (req, res) => {
  return res.status(404).json({
    message: "Retouche introuvable",
    error: "NOT_FOUND",
    statusCode: 404,
  });
});

createRoles();
getKey()

// Gestion globale des erreurs
app.use((err, req, res, next) => {
  console.error("Erreur globale:", err.stack);

  return res.status(err.status || 500).json({
    message: err.message || "Erreur interne du serveur",
    error: err?.error || "INTERNAL_ERROR",
    statusCode: err?.statusCode || 500,
  });
});
