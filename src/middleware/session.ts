import { Request, Response, NextFunction } from "express";
import { verifyToken } from "../utils/jwt.handle.js";
import { JwtPayload } from "jsonwebtoken";

interface RequestExt extends Request {
    user?: string | JwtPayload;
}

// Claves secretas para access y refresh tokens
const ACCESS_SECRET = process.env.JWT_SECRET || "default_access_secret";
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "default_refresh_secret";

/**
 * Middleware para verificar el token JWT.
 * @param isRefreshToken Indica si se está verificando un refresh token.
 */
const checkJwt = (isRefreshToken: boolean = false) => {
    return (req: RequestExt, res: Response, next: NextFunction) => {
        try {
            const jwtByUser = req.headers.authorization || null;
            const jwt = jwtByUser?.split(" ").pop(); // ['Bearer', '11111'] -> ['11111']

            if (!jwt) {
                return res.status(401).send("NO_TIENES_UN_JWT_VALIDO");
            }

            // Selecciona la clave secreta según el tipo de token
            const secret = isRefreshToken ? REFRESH_SECRET : ACCESS_SECRET;

            // Verifica el token
            const isUser = verifyToken(jwt, isRefreshToken ? "refresh" : "access");

            if (!isUser) {
                return res.status(401).send("NO_TIENES_UN_JWT_VALIDO");
            }

            // Adjunta los datos del token al objeto `req`
            req.user = isUser;
            next(); // Solo si el token es válido, pasa al siguiente middleware
        } catch (e) {
            console.error("Error en checkJwt:", e);
            return res.status(401).send("SESSION_NO_VALID");
        }
    };
};

export { checkJwt };
