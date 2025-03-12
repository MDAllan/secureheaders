module.exports = (req, res, next) => {
    if (req.user && req.user.role === "admin") {
      return next();
    }
    return res.status(403).json({ msg: "Access denied. You do not have admin privileges." });
  };
  