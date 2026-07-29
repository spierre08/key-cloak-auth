import { string, object } from "yup";

export class AuthValidator {
  static registerSchemaValidator = object({
    body: object({
      username: string()
        .typeError("Le nom utilisateur doit être une chaine")
        .required("Le nom utilisateur est requis"),

      firstName: string()
        .typeError("Le prénom doit être une chaine")
        .required("Le prénom est requis"),

      lastName: string()
        .typeError("Le nom doit être une chaine")
        .required("Le nom est requis"),

      email: string()
        .typeError("L'email doit être une chaine")
        .required("L'email est requis")
        .email("L'email est invalide"),

      password: string()
        .typeError("Le mot de passe doit être une chaine")
        .min(6, "Le mot de passe doit être 6 caractères")
        .required("Le mot de passe est requis"),
    }),
  });

  static loginSchemaValidator = object({
    body: object({
      username: string()
        .typeError("Le nom utilisateur doit être une chaine")
        .required("Le nom utilisateur est requis"),

      password: string()
        .typeError("Le mot de passe doit être une chaine")
        .required("Le mot de passe est requis"),
    }),
  });
}
