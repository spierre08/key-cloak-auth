import jwt from "jsonwebtoken";
import { UserModel } from "../models/User.js";
import { KeyCloakConfig } from "../config/keycloak.config.js";
import { EnvConfig } from "../config/env.config.js";

export class AuthController {
  // Inscription
  static register = async (req, res) => {
    try {
      const {
        username,
        email,
        password,
        firstName,
        lastName,
        roles = ["user"],
      } = req.body;

      // Validation des roles
      const validRoles = ["admin", "moderator", "user", "premium"];
      if (roles && roles.length > 0) {
        const invalidRoles = roles.filter((role) => !validRoles.includes(role));
        if (invalidRoles.length > 0) {
          return res.status(400).json({
            message: `Roles invalides: ${invalidRoles.join(", ")}`,
            validRoles: validRoles,
            error: "VALIDATION_ERROR",
            statusCode: 400,
          });
        }
      }

      // Verifier si l'utilisateur existe deja
      const existingUser = await UserModel.findOne({
        $or: [{ email: email.toLowerCase() }, { username }],
      });

      if (existingUser) {
        return res.status(409).json({
          message: "Cet utilisateur existe deja",
          error: "CONFLICT",
          statusCode: 409,
        });
      }

      // Creer l'utilisateur dans Keycloak avec roles
      const { userId, roles: assignedRoles } =
        await KeyCloakConfig.createKeycloakUser({
          username,
          email: email.toLowerCase(),
          password,
          firstName,
          lastName,
          roles: roles || ["user"],
        });

      // Creer l'utilisateur dans la DB
      const newUser = new UserModel({
        keycloakId: userId,
        username,
        email: email.toLowerCase(),
        firstName: firstName || "",
        lastName: lastName || "",
        roles: assignedRoles || ["user"],
      });

      await newUser.save();

      const userResponse = newUser.toObject();
      delete userResponse.__v;

      return res.status(201).json({
        message: "Utilisateur cree avec succes",
        user: userResponse,
        assignedRoles: assignedRoles,
        statusCode: 201,
      });
    } catch (error) {
      console.error("Erreur inscription:", error);
      return res.status(500).json({
        message: error.message || "Erreur lors de l'inscription",
        error: "INTERNAL_SERVER_ERROR",
        statusCode: 500,
      });
    }
  };

  // Connexion
  static login = async (req, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(400).json({
          message: "Username et password sont requis",
          error: "VALIDATION_ERROR",
          statusCode: 400,
        });
      }

      // Authentifier via Keycloak
      const tokenData = await KeyCloakConfig.authenticateKeycloakUser(
        username,
        password
      );

      // Decoder le token pour obtenir le sub
      const decoded = jwt.decode(tokenData.accessToken);
      if (!decoded || !decoded.sub) {
        return res.status(401).json({
          message: "Token invalide",
          error: "INVALID_TOKEN",
          statusCode: 401,
        });
      }

      // Recuperer l'utilisateur MongoDB
      const user = await UserModel.findOne({ keycloakId: decoded.sub });
      if (!user) {
        return res.status(404).json({
          message: "Utilisateur non trouve en base de donnees",
          error: "NOT_FOUND",
          statusCode: 404,
        });
      }

      // Verifier si le compte est actif
      if (!user.isActive) {
        return res.status(403).json({
          message: "Compte desactive",
          error: "FORBIDDEN",
          statusCode: 403,
        });
      }

      // Mettre a jour la date de derniere connexion
      user.lastLogin = new Date();
      await user.save();

      // Generer notre propre token
      const expiresIn = EnvConfig.jwtExpiresIn || 604800;
      const ourToken = AuthController.generateToken(user, expiresIn);

      const userResponse = user.toObject();
      delete userResponse.__v;

      return res.status(200).json({
        message: "Authentification reussie",
        tokens: {
          accessToken: ourToken,
          refreshToken: ourToken,
          expiresIn: expiresIn,
          tokenType: "Bearer",
        },
        user: userResponse,
        statusCode: 200,
      });
    } catch (error) {
      console.error("Erreur login:", error);
      return res.status(401).json({
        message: error.message || "Identifiants invalides",
        error: "UNAUTHORIZED",
        statusCode: 401,
      });
    }
  };

  // Generer un token JWT avec HS256
  static generateToken = (user, expiresIn = 604800) => {
    const payload = {
      sub: user.keycloakId,
      username: user.username,
      email: user.email,
      roles: user.roles,
      userId: user._id.toString(),
      iat: Math.floor(Date.now() / 1000),
    };

    return jwt.sign(
      payload,
      EnvConfig.jwtSecret || "votre-secret-jwt-changez-moi",
      {
        expiresIn: expiresIn,
        algorithm: "HS256",
      }
    );
  };

  // Verifier un token JWT
  static verifyTokenJWT = (token) => {
    try {
      return jwt.verify(
        token,
        EnvConfig.jwtSecret || "votre-secret-jwt-changez-moi",
        {
          algorithms: ["HS256"],
        }
      );
    } catch (error) {
      throw error;
    }
  };

  // Decoder un token sans verification
  static decodeToken = (token) => {
    try {
      return jwt.decode(token);
    } catch (error) {
      console.error("Token decode error:", error.message);
      return null;
    }
  };

  // Rafraichir le token
  static refreshToken = async (req, res) => {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({
          message: "Refresh token requis",
          error: "VALIDATION_ERROR",
          statusCode: 400,
        });
      }

      // Decoder le token sans verification pour voir son contenu
      const decodedToken = AuthController.decodeToken(refreshToken);

      if (!decodedToken) {
        return res.status(401).json({
          message: "Refresh token invalide - impossible de decoder",
          error: "UNAUTHORIZED",
          statusCode: 401,
        });
      }

      // Verifier le refresh token
      let verified;
      try {
        verified = AuthController.verifyTokenJWT(refreshToken);
      } catch (error) {
        if (error.name === "TokenExpiredError") {
          return res.status(401).json({
            message: "Refresh token expire, veuillez vous reconnecter",
            error: "TOKEN_EXPIRED",
            statusCode: 401,
            requiresLogin: true,
          });
        }

        return res.status(401).json({
          message: "Refresh token invalide",
          error: "UNAUTHORIZED",
          statusCode: 401,
          details: error.message,
        });
      }

      // Verifier que le token contient un userId
      if (!verified.userId) {
        return res.status(401).json({
          message: "Refresh token invalide - userId manquant",
          error: "UNAUTHORIZED",
          statusCode: 401,
        });
      }

      // Recuperer l'utilisateur
      const user = await UserModel.findById(verified.userId);
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

      // Generer un nouveau token
      const expiresIn = EnvConfig.jwtExpiresIn || 604800;
      const newToken = AuthController.generateToken(user, expiresIn);

      return res.status(200).json({
        message: "Token rafraichi avec succes",
        tokens: {
          accessToken: newToken,
          refreshToken: newToken,
          expiresIn: expiresIn,
          tokenType: "Bearer",
        },
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          roles: user.roles,
        },
        statusCode: 200,
      });
    } catch (error) {
      console.error("Erreur refresh:", error);
      return res.status(500).json({
        message: error.message || "Erreur lors du rafraichissement",
        error: "INTERNAL_SERVER_ERROR",
        statusCode: 500,
      });
    }
  };

  // Obtenir le profil
  static getProfile = async (req, res) => {
    try {
      const user = req.user;

      if (!user) {
        return res.status(401).json({
          message: "Utilisateur non authentifie",
          error: "UNAUTHORIZED",
          statusCode: 401,
        });
      }

      const userResponse = user.toObject();
      delete userResponse.__v;

      return res.status(200).json({
        message: "Profil recupere avec succes",
        user: userResponse,
        permissions: {
          isAdmin: user.isAdmin ? user.isAdmin() : false,
          isPremium: user.isPremium ? user.isPremium() : false,
        },
        statusCode: 200,
      });
    } catch (error) {
      console.error("Erreur profil:", error);
      return res.status(500).json({
        message: error.message || "Erreur lors de la recuperation du profil",
        error: "INTERNAL_SERVER_ERROR",
        statusCode: 500,
      });
    }
  };

  // Mettre a jour le profil
  static updateProfile = async (req, res) => {
    try {
      const { firstName, lastName, profile } = req.body;
      const user = req.user;

      if (!user) {
        return res.status(401).json({
          message: "Utilisateur non authentifie",
          error: "UNAUTHORIZED",
          statusCode: 401,
        });
      }

      if (firstName !== undefined) user.firstName = firstName;
      if (lastName !== undefined) user.lastName = lastName;

      if (profile) {
        user.profile = {
          ...user.profile,
          bio: profile.bio !== undefined ? profile.bio : user.profile?.bio,
          avatar:
            profile.avatar !== undefined
              ? profile.avatar
              : user.profile?.avatar,
          phone:
            profile.phone !== undefined ? profile.phone : user.profile?.phone,
          address: profile.address
            ? {
                ...user.profile?.address,
                ...profile.address,
              }
            : user.profile?.address,
          preferences: profile.preferences
            ? {
                ...user.profile?.preferences,
                ...profile.preferences,
              }
            : user.profile?.preferences,
        };
      }

      await user.save();

      const userResponse = user.toObject();
      delete userResponse.__v;

      return res.status(200).json({
        message: "Profil mis a jour avec succes",
        user: userResponse,
        statusCode: 200,
      });
    } catch (error) {
      console.error("Erreur mise a jour profil:", error);
      return res.status(500).json({
        message: error.message || "Erreur lors de la mise a jour du profil",
        error: "INTERNAL_SERVER_ERROR",
        statusCode: 500,
      });
    }
  };

  // Deconnexion
  static logout = async (req, res) => {
    try {
      const refreshToken =
        req.body.refreshToken || req.headers["x-refresh-token"];

      if (!refreshToken) {
        return res.status(400).json({
          message: "Refresh token requis",
          error: "VALIDATION_ERROR",
          statusCode: 400,
        });
      }

      try {
        await KeyCloakConfig.logoutKeycloakUser(refreshToken);
      } catch (error) {
        console.warn("Erreur logout Keycloak:", error.message);
      }

      return res.status(200).json({
        message: "Deconnecte avec succes",
        statusCode: 200,
      });
    } catch (error) {
      console.error("Erreur deconnexion:", error);
      return res.status(500).json({
        message: error.message || "Erreur lors de la deconnexion",
        error: "INTERNAL_SERVER_ERROR",
        statusCode: 500,
      });
    }
  };

  // Verifier le token
  static verifyToken = async (req, res) => {
    try {
      const user = req.user;

      if (!user) {
        return res.status(401).json({
          message: "Token invalide",
          error: "UNAUTHORIZED",
          statusCode: 401,
        });
      }

      return res.status(200).json({
        message: "Token valide",
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          roles: user.roles,
        },
        statusCode: 200,
      });
    } catch (error) {
      console.error("Erreur verification token:", error);
      return res.status(500).json({
        message: error.message || "Erreur lors de la verification du token",
        error: "INTERNAL_SERVER_ERROR",
        statusCode: 500,
      });
    }
  };

  // Ajouter des roles (admin seulement)
  static addRoles = async (req, res) => {
    try {
      const { userId, roles } = req.body;
      const currentUser = req.user;

      if (!currentUser || !currentUser.isAdmin()) {
        return res.status(403).json({
          message: "Seul un admin peut attribuer des roles",
          error: "FORBIDDEN",
          statusCode: 403,
        });
      }

      const user = await UserModel.findById(userId);
      if (!user) {
        return res.status(404).json({
          message: "Utilisateur non trouve",
          error: "NOT_FOUND",
          statusCode: 404,
        });
      }

      await KeyCloakConfig.assignRolesToUser(user.keycloakId, roles);

      for (const role of roles) {
        if (!user.roles.includes(role)) {
          user.roles.push(role);
        }
      }
      await user.save();

      return res.status(200).json({
        message: "Roles ajoutes avec succes",
        user: {
          id: user._id,
          username: user.username,
          roles: user.roles,
        },
        statusCode: 200,
      });
    } catch (error) {
      console.error("Erreur ajout roles:", error);
      return res.status(500).json({
        message: error.message || "Erreur lors de l'ajout des roles",
        error: "INTERNAL_SERVER_ERROR",
        statusCode: 500,
      });
    }
  };

  // Supprimer des roles (admin seulement)
  static removeRoles = async (req, res) => {
    try {
      const { userId, roles } = req.body;
      const currentUser = req.user;

      if (!currentUser || !currentUser.isAdmin()) {
        return res.status(403).json({
          message: "Seul un admin peut supprimer des roles",
          error: "FORBIDDEN",
          statusCode: 403,
        });
      }

      const user = await UserModel.findById(userId);
      if (!user) {
        return res.status(404).json({
          message: "Utilisateur non trouve",
          error: "NOT_FOUND",
          statusCode: 404,
        });
      }

      if (roles.includes("user") && user.roles.length === 1 && user.roles.includes("user")) {
        return res.status(400).json({
          message: 'Un utilisateur doit avoir au moins le role "user"',
          error: "VALIDATION_ERROR",
          statusCode: 400,
        });
      }

      await KeyCloakConfig.removeRolesFromUser(user.keycloakId, roles);

      for (const role of roles) {
        user.roles = user.roles.filter((r) => r !== role);
      }
      await user.save();

      return res.status(200).json({
        message: "Roles supprimes avec succes",
        user: {
          id: user._id,
          username: user.username,
          roles: user.roles,
        },
        statusCode: 200,
      });
    } catch (error) {
      console.error("Erreur suppression roles:", error);
      return res.status(500).json({
        message: error.message || "Erreur lors de la suppression des roles",
        error: "INTERNAL_SERVER_ERROR",
        statusCode: 500,
      });
    }
  };
}