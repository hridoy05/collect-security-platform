export interface AuthTokenPayload {
  userId: string;
  email: string;
  role?: string | null;
  iat?: number;
  exp?: number;
}
