const { prisma } = require('./db');

class UserRepository {
  async findByEmail(email) {
    return await prisma.user.findUnique({ where: { email } });
  }
}

class RefreshTokenRepository {
  async create(token, userId, expiresAt) {
    return await prisma.refreshToken.create({
      data: { token, userId, expiresAt }
    });
  }

  async findByToken(token) {
    return await prisma.refreshToken.findUnique({ where: { token } });
  }

  async revoke(id) {
    await prisma.refreshToken.update({
      where: { id },
      data: { isRevoked: true }
    });
  }

  async revokeAllUserTokens(userId) {
    await prisma.refreshToken.updateMany({
      where: { userId },
      data: { isRevoked: true }
    });
  }
}

module.exports = { UserRepository, RefreshTokenRepository };