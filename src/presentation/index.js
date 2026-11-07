require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const { prisma } = require('../infrastructure/db');
const { UserRepository, RefreshTokenRepository } = require('../infrastructure/repositories');
const { AuthService } = require('../application/auth.service');
const { AuthController } = require('./auth.controller');

const app = express();
app.use(express.json());

// Inyección de dependencias
const userRepo = new UserRepository();
const refreshTokenRepo = new RefreshTokenRepository();
const authService = new AuthService(userRepo, refreshTokenRepo);
const authController = new AuthController(authService);

app.post('/auth/login', authController.login);
app.post('/auth/refresh', authController.refresh);
app.post('/auth/logout', authController.logout);

async function bootstrap() {
  const userExists = await prisma.user.findUnique({ where: { email: 'admin@test.com' } });
  if (!userExists) {
    const password = await bcrypt.hash('123456', 10);
    await prisma.user.create({ data: { email: 'admin@test.com', password } });
    console.log('Usuario inicial creado: admin@test.com / 123456');
  }

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Servidor iniciado en http://localhost:${PORT}`);
  });
}

bootstrap();