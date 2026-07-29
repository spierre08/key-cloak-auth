import { Schema, model } from "mongoose";

const Userschema = new Schema(
  {
    keycloakId: {
      type: String,
      index: true,
    },
    username: {
      type: String,
      unique: true,
    },
    email: {
      type: String,
      unique: true,
    },
    firstName: String,
    lastName: String,
    roles: {
      type: [String],
      enum: ["admin", "moderator", "user", "premium"],
      default: ["user"],
    },
    profile: {
      bio: String,
      avatar: String,
      phone: String,
      address: String,
      preferences: {
        notifications: { type: Boolean, default: true },
        language: { type: String, default: "fr" },
      },
    },
    lastLogin: Date,
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true, collection: "users" },
);

export const UserModel = model("User", Userschema);
