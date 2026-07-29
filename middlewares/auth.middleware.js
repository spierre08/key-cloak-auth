import axios from "axios";
import jwt from "jsonwebtoken";
import { UserModel } from "../models/User.js";
import { EnvConfig } from "../config/env.config.js";

export const authenticateJWT = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Token manquant",
        error: "UNAUTHORIZED",
        statusCode: 401,
      });
    }

    const token = authHeader.split(" ")[1];

    // Decoder le token pour inspection
    const decodedToken = jwt.decode(token);
   
    // Verifier le token avec HS256 (symetrique)
    let decoded;
    try {
      // Utiliser le meme secret que pour la generation
      decoded = jwt.verify(
        token,
        EnvConfig.jwtSecret,
        {
          algorithms: ["HS256"],
          ignoreExpiration: false,
        },
      );
      console.log("Token verifie avec HS256");
    } catch (error) {
      console.error("Erreur verification HS256:", error.message);

      // Si HS256 echoue, essayer sans algorithme specifique
      try {
        decoded = jwt.verify(
          token,
          EnvConfig.jwtSecret,
          {
            ignoreExpiration: false,
          },
        );
        console.log("Token verifie sans algorithme specifique");
      } catch (error2) {
        console.error("Erreur seconde tentative:", error2.message);
        throw error2;
      }
    }

    // Recuperer l'utilisateur
    const user = await UserModel.findOne({ keycloakId: decoded.sub });
    if (!user) {
      return res.status(404).json({
        message: "Utilisateur non trouve",
        error: "NOT_FOUND",
        statusCode: 404,
      });
    }

    if (!user.isActive) {
      return res.status(403).json({
        message: "Compte desactive",
        error: "FORBIDDEN",
        statusCode: 403,
      });
    }

    req.user = user;
    req.keycloakUser = decoded;
    req.token = token;

    next();
  } catch (error) {
    console.error("Erreur JWT:", error.message);

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        message: "Token expire",
        error: "TOKEN_EXPIRED",
        statusCode: 401,
      });
    }

    return res.status(403).json({
      message: "Token invalide",
      error: "INVALID_TOKEN",
      statusCode: 403,
      details: error.message,
    });
  }
};

// Middleware de verification des roles
export const checkRole = (requiredRoles) => {
  return (req, res, next) => {
    const userRoles = req.user?.roles || [];
    const roles = Array.isArray(requiredRoles)
      ? requiredRoles
      : [requiredRoles];
    const hasRole = roles.some((role) => userRoles.includes(role));

    if (!hasRole) {
      return res.status(403).json({
        message: "Acces refuse - Role insuffisant",
        error: "FORBIDDEN",
        statusCode: 403,
        // requiredRoles: roles,
        // userRoles: userRoles,
      });
    }

    next();
  };
};

// Middleware optionnel (authentification si token present)
export const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      req.user = null;
      return next();
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, EnvConfig.jwtSecret, {
      algorithms: ["HS256"],
      ignoreExpiration: false,
    });

    const user = await UserModel.findOne({ keycloakId: decoded.sub });
    req.user = user || null;
    req.keycloakUser = decoded || null;
    req.token = token;

    next();
  } catch (error) {
    req.user = null;
    next();
  }
};
