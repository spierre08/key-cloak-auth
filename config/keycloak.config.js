// config/keycloak.config.js
import axios from "axios";
import { EnvConfig } from "./env.config.js";

const {
  keyCloakUrl: KEYCLOAK_URL,
  keyCloakRealM: REALM,
  keyCloakClientId: CLIENT_ID,
  keyCloakClientSecret: CLIENT_SECRET,
  keyCloakAdminName: ADMIN_USER,
  keyCloakAdminPassword: ADMIN_PASSWORD,
} = EnvConfig;

export class KeyCloakConfig {
  // Obtenir un token admin
  static getAdminToken = async () => {
    try {
      const params = new URLSearchParams({
        grant_type: "password",
        client_id: "admin-cli",
        username: ADMIN_USER,
        password: ADMIN_PASSWORD,
      });

      const response = await axios.post(
        `${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token`,
        params.toString(),
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
        },
      );

      return response.data.access_token;
    } catch (error) {
      console.error(
        "Erreur admin token:",
        error.response?.data || error.message,
      );
      throw new Error(
        error.response?.data?.error_description ||
          "Impossible d'obtenir le token admin",
      );
    }
  };

  // Creer un utilisateur avec roles
  static createKeycloakUser = async (userData) => {
    const adminToken = await this.getAdminToken();

    const {
      username,
      email,
      password,
      firstName,
      lastName,
      roles = ["user"],
    } = userData;

    try {
      const response = await axios.post(
        `${KEYCLOAK_URL}/admin/realms/${REALM}/users`,
        {
          username,
          email,
          enabled: true,
          emailVerified: true,
          firstName: firstName || "",
          lastName: lastName || "",
          credentials: [
            {
              type: "password",
              value: password,
              temporary: false,
            },
          ],
        },
        {
          headers: {
            Authorization: `Bearer ${adminToken}`,
            "Content-Type": "application/json",
          },
        },
      );

      const location = response.headers.location;
      const userId = location.split("/").pop();

      let assignedRoles = [];
      if (roles && roles.length > 0) {
        assignedRoles = await this.assignRolesToUser(userId, roles, adminToken);
      }

      return {
        userId,
        roles: assignedRoles.map((r) => r.name),
      };
    } catch (error) {
      console.error(
        "Erreur creation Keycloak:",
        error.response?.data || error.message,
      );

      if (error.response?.data?.errorMessage) {
        throw new Error(error.response.data.errorMessage);
      }
      throw new Error("Impossible de creer l'utilisateur dans Keycloak");
    }
  };

  // Attribuer des roles a un utilisateur
  static assignRolesToUser = async (userId, roles, adminToken) => {
    try {
      const token = adminToken || (await this.getAdminToken());

      const realmRoles = await this.getRealmRoles(token);

      const rolesToAssign = realmRoles
        .filter((role) => roles.includes(role.name))
        .map((role) => ({
          id: role.id,
          name: role.name,
        }));

      if (rolesToAssign.length === 0) {
        console.warn("Aucun role valide a attribuer");
        return [];
      }

      await axios.post(
        `${KEYCLOAK_URL}/admin/realms/${REALM}/users/${userId}/role-mappings/realm`,
        rolesToAssign,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        },
      );

      return rolesToAssign;
    } catch (error) {
      console.error(
        "Erreur assignation roles:",
        error.response?.data || error.message,
      );
      throw new Error("Impossible d'attribuer les roles");
    }
  };

  // Obtenir tous les roles du realm
  static getRealmRoles = async (adminToken) => {
    try {
      const token = adminToken || (await this.getAdminToken());
      const response = await axios.get(
        `${KEYCLOAK_URL}/admin/realms/${REALM}/roles`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
      );
      return response.data;
    } catch (error) {
      console.error("Erreur recuperation roles:", error.message);
      return [];
    }
  };

  // Authentifier un utilisateur - TOKEN VALABLE 7 JOURS
  static authenticateKeycloakUser = async (username, password) => {
    try {
      // Augmenter la duree de vie du token a 7 jours (604800 secondes)
      const params = new URLSearchParams({
        grant_type: "password",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        username,
        password,
        // Ajouter la duree de vie du token en secondes (7 jours)
      });

      const response = await axios.post(
        `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`,
        params.toString(),
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
        },
      );

      // Modifier la duree de vie du token a 7 jours
      const accessToken = response.data.access_token;
      const refreshToken = response.data.refresh_token;
      const expiresIn = 604800; // 7 jours en secondes

      return {
        accessToken,
        refreshToken,
        expiresIn: expiresIn,
        tokenType: response.data.token_type || "Bearer",
      };
    } catch (error) {
      console.error(
        "Erreur authentication:",
        error.response?.data || error.message,
      );

      if (error.response?.status === 401) {
        throw new Error("Identifiants invalides");
      }
      throw new Error(error.message || "Erreur lors de l'authentification");
    }
  };

  // Deconnecter l'utilisateur
  static logoutKeycloakUser = async (refreshToken) => {
    try {
      if (!refreshToken) {
        throw new Error("Refresh token requis");
      }

      const params = new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: refreshToken,
      });

      await axios.post(
        `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/logout`,
        params.toString(),
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
        },
      );

      return true;
    } catch (error) {
      console.error("Erreur logout:", error.response?.data || error.message);
      throw new Error(error.message || "Erreur lors de la deconnexion");
    }
  };

  // Recuperer les roles d'un utilisateur
  static getUserRoles = async (userId, adminToken) => {
    try {
      const token = adminToken || (await this.getAdminToken());
      const response = await axios.get(
        `${KEYCLOAK_URL}/admin/realms/${REALM}/users/${userId}/role-mappings/realm`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
      );
      return response.data;
    } catch (error) {
      console.error("Erreur recuperation roles user:", error.message);
      return [];
    }
  };
}
