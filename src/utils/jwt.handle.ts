import pkg from "jsonwebtoken";
const { sign, verify } = pkg; // Importamos las funciones sign y verify de la librería jsonwebtoken

const JWT_SECRET = process.env.JWT_SECRET || "token.010101010101";
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || "token.1010101010101";

/**
 * Genera un access token.
 * @param id El ID del usuario.
 */
const generateToken = (id: string) => {
    const jwt = sign({ id }, JWT_SECRET, { expiresIn: '20s' });
    return jwt;
};

/**
 * Verifica un token JWT (access o refresh).
 * @param jwt El token a verificar.
 * @param type El tipo de token: "access" o "refresh".
 * @returns Los datos decodificados si el token es válido, o null si no lo es.
 */
const verifyToken = (jwt: string, type: "access" | "refresh" = "access") => {
    try {
        const secret = type === "access" ? JWT_SECRET : REFRESH_TOKEN_SECRET;
        return verify(jwt, secret); // Devuelve los datos decodificados si el token es válido
    } catch (error) {
        console.error("Error al verificar el token:", error);
        return null; // Devuelve null si el token no es válido
    }
};

/**
 * Genera un refresh token.
 * @param id El ID del usuario.
 */
const generateRefreshToken = (id: string) => {
    const refreshToken = sign({ id }, REFRESH_TOKEN_SECRET, { expiresIn: '1d' });
    return refreshToken;
};

export { generateToken, verifyToken, generateRefreshToken };