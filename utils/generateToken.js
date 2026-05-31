import jwt from 'jsonwebtoken';

export const generateToken = (id, isAdmin = false) => {
  return jwt.sign({ id, isAdmin }, process.env.JWT_SECRET);
};




