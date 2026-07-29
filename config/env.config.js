import dotenv from "dotenv";

dotenv.config();

export class EnvConfig {
  static apiPrefix = process.env.API_PREFIX;
  static port = process.env.PORT;
  static mongoose_uri = process.env.MONGO_URI;
  static keyCloakRealM = process.env.KEYCLOAK_REALM;
  static keyCloakUrl = process.env.KEYCLOAK_URL;
  static keyCloakClientId = process.env.KEYCLOAK_CLIENT_ID;
  static keyCloakClientSecret = process.env.KEYCLOAK_CLIENT_SECRET;
  static keyCloakAdminName = process.env.KEYCLOAK_ADMIN_USER;
  static keyCloakAdminPassword = process.env.KEYCLOAK_ADMIN_PASSWORD;
  static jwtSecret = process.env.JWT_SECRET;
}
