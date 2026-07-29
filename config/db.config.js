import mongoose from "mongoose";
import { EnvConfig } from "./env.config.js";

export const ConnectDb = async () => {
  try {
    await mongoose.connect(EnvConfig.mongoose_uri);
    console.log("Connexion à la base de données.");
  } catch (error) {
    console.error("Erreur de connection à la base de données", error?.message);
  }
};
