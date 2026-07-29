import axios from "axios";

export const getKey = async () => {
  try {
    // Essayer avec le realm configuré
    let url = "http://localhost:8080/realms/master/protocol/openid-connect/certs";
    console.log("Récupération depuis:", url);
    
    const response = await axios.get(url);
    const keys = response.data.keys;
    
    console.log(`\nNombre de clés: ${keys.length}`);
    
    keys.forEach((key, index) => {
      console.log(`\nClé ${index + 1}:`);
      console.log(`  kid: ${key.kid}`);
      console.log(`  alg: ${key.alg}`);
      console.log(`  use: ${key.use}`);
      if (key.x5c && key.x5c.length > 0) {
        console.log(`  x5c: ${key.x5c[0].substring(0, 50)}...`);
        console.log(`\n  -----BEGIN CERTIFICATE-----`);
        console.log(`  ${key.x5c[0]}`);
        console.log(`  -----END CERTIFICATE-----`);
      }
    });
    
  } catch (error) {
    console.error("Erreur:", error.message);
  }
};
