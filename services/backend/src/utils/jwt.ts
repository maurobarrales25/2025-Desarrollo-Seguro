import jwt from 'jsonwebtoken';
import config from '../config';

const generateToken = (userId: number) => {   // cambio a number
  return jwt.sign(
    { id: userId }, 
    config.jwt.secret, 
    { expiresIn: '1h' }
  );
};

const verifyToken = (token: string) => {
  return jwt.verify(token, config.jwt.secret);
};

export default {
  generateToken,
  verifyToken
}