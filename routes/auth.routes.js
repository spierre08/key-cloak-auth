import { Router } from "express";
import {
  authenticateJWT,
  checkRole,
  optionalAuth,
} from "../middlewares/auth.middleware.js";
import { validatorMiddleware } from "../middlewares/validate.middleware.js";
import { AuthController } from "../controllers/auth.controller.js";
import { AuthValidator } from "../validators/auth.validator.js";

export const AuthRoutes = Router();

// Routes publiques
AuthRoutes.post(
  "/register",
  validatorMiddleware(AuthValidator.registerSchemaValidator),
  AuthController.register,
);

AuthRoutes.post(
  "/login",
  validatorMiddleware(AuthValidator.loginSchemaValidator),
  AuthController.login,
);

AuthRoutes.post("/refresh-token", AuthController.refreshToken);

AuthRoutes.post("/logout", AuthController.logout);

// Routes protégées (authentification requise)
AuthRoutes.get("/profile", authenticateJWT, AuthController.getProfile);

AuthRoutes.put(
  "/update-profile",
  authenticateJWT,
  AuthController.updateProfile,
);

AuthRoutes.get("/verify", authenticateJWT, AuthController.verifyToken);

// Routes avec rôles spécifiques
AuthRoutes.get("/admin", authenticateJWT, checkRole("admin"), (req, res) => {
  return res.json({
    message: "Accès admin accordé",
    user: req.user,
  });
});

// Route avec authentification optionnelle
AuthRoutes.get("/public-with-user", optionalAuth, (req, res) => {
  return res.json({
    message: req.user ? "Utilisateur authentifié" : "Utilisateur anonyme",
    user: req.user || null,
  });
});
