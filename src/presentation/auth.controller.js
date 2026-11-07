class AuthController {
  constructor(authService) {
    this.authService = authService;
  }

  login = async (req, res) => {
    try {
      const { email, password } = req.body;
      const tokens = await this.authService.login(email, password);
      res.json(tokens);
    } catch (err) {
      res.status(401).json({ error: err.message });
    }
  };

  refresh = async (req, res) => {
    try {
      const { refreshToken } = req.body;
      const tokens = await this.authService.refresh(refreshToken);
      res.json(tokens);
    } catch (err) {
      res.status(403).json({ error: err.message });
    }
  };

  logout = async (req, res) => {
    try {
      const { userId } = req.body;
      await this.authService.logout(userId);
      res.json({ message: 'Revocación total realizada con éxito' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  };
}

module.exports = { AuthController };