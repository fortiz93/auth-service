const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

class AuthService {
  constructor(userRepo, refreshTokenRepo) {
    this.userRepo = userRepo;
    this.refreshTokenRepo = refreshTokenRepo;
  }

  generateAccessToken(userId) {
    return jwt.sign({ sub: userId }, process.env.JWT_ACCESS_SECRET || 'access_secret', { expiresIn: '15m' });
  }

  generateRefreshToken(userId) {
    return jwt.sign({ sub: userId }, process.env.JWT_REFRESH_SECRET || 'refresh_secret', { expiresIn: '7d' });
  }

  async login(email, password) {
    const user = await this.userRepo.findByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new Error('Credenciales inválidas');
    }

    const accessToken = this.generateAccessToken(user.id);
    const refreshToken = this.generateRefreshToken(user.id);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await this.refreshTokenRepo.create(refreshToken, user.id, expiresAt);

    return { accessToken, refreshToken };
  }

  async refresh(oldRefreshToken) {
    try {
      jwt.verify(oldRefreshToken, process.env.JWT_REFRESH_SECRET || 'refresh_secret');
    } catch (err) {
      throw new Error('Refresh token expirado o firma inválida');
    }

    const storedToken = await this.refreshTokenRepo.findByToken(oldRefreshToken);

    if (!storedToken || storedToken.isRevoked || new Date() > storedToken.expiresAt) {
      throw new Error('Refresh Token inválido o revocado');
    }

    // 1. Invalida el token anterior (Rotación)
    await this.refreshTokenRepo.revoke(storedToken.id);

    // 2. Genera y guarda nuevo par de tokens
    const newAccessToken = this.generateAccessToken(storedToken.userId);
    const newRefreshToken = this.generateRefreshToken(storedToken.userId);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await this.refreshTokenRepo.create(newRefreshToken, storedToken.userId, expiresAt);

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  async logout(userId) {
    // Revocación total
    await this.refreshTokenRepo.revokeAllUserTokens(userId);
  }
}

module.exports = { AuthService };