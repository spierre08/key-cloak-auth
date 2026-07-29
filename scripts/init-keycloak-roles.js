import axios from "axios";
import dotenv from "dotenv";
import { EnvConfig } from "../config/env.config.js";

dotenv.config();

const KEYCLOAK_URL = EnvConfig.keyCloakUrl;
const REALM = EnvConfig.keyCloakRealM;
const ADMIN_USER = EnvConfig.keyCloakAdminName;
const ADMIN_PASSWORD = EnvConfig.keyCloakAdminPassword;

const getAdminToken = async () => {
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
        timeout: 10000,
      }
    );

    if (!response.data.access_token) {
      throw new Error("Aucun token recu");
    }

    return response.data.access_token;
  } catch (error) {
    if (error.code === "ECONNREFUSED") {
      console.error("Erreur: Keycloak n'est pas accessible sur", KEYCLOAK_URL);
      console.error("Veuillez demarrer Keycloak avec: docker start keycloak");
    } else {
      console.error("Erreur lors de l'obtention du token admin:", error.response?.data || error.message);
    }
    throw error;
  }
};

export const createRoles = async () => {
  try {
    const adminToken = await getAdminToken();


    // Verifier que le realm existe
    try {
      await axios.get(`${KEYCLOAK_URL}/admin/realms/${REALM}`, {
        headers: {
          Authorization: `Bearer ${adminToken}`,
        },
      });
      console.log(`Realm "${REALM}" trouve avec succes`);
    } catch (error) {
      if (error.response?.status === 404) {
        console.error(`Erreur: Le realm "${REALM}" n'existe pas`);
        console.error("Veuillez creer le realm dans Keycloak avant d'executer ce script");
        process.exit(1);
      }
      throw error;
    }

    const roles = ["admin", "moderator", "user", "premium"];

    console.log(`Creation des roles dans le realm "${REALM}"...`);

    for (const role of roles) {
      try {
        await axios.post(
          `${KEYCLOAK_URL}/admin/realms/${REALM}/roles`,
          {
            name: role,
            description: `Role ${role}`,
          },
          {
            headers: {
              Authorization: `Bearer ${adminToken}`,
              "Content-Type": "application/json",
            },
          }
        );
        console.log(`[OK] Role "${role}" cree avec succes`);
      } catch (error) {
        if (error.response?.status === 409) {
          console.log(`[INFO] Role "${role}" existe deja`);
        } else {
          console.error(`[ERREUR] Creation role "${role}":`);
          console.error("  Status:", error.response?.status);
          console.error("  Message:", error.response?.data?.errorMessage || error.message);
        }
      }
    }

    console.log("----------------------------------------");
    console.log("Initialisation des roles terminee !");
  } catch (error) {
    console.error("Erreur fatale:", error.message);
    process.exit(1);
  }
};
