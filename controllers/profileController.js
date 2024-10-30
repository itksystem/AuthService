const User = require('../models/userModel');

exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }
    res.json({ id: user.id, email: user.email, name: user.name });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.updateProfile = async (req, res) => {
  const { name, email} = req.body;

  try {
    const user = await User.update(req.user.id, name, email);
    res.json({ message: 'Профиль обновлен успешно!', user });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
