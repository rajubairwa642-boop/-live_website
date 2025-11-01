// userModel.js
let users = [];

function createUser({ id, name, email, password }) {
  const user = { id, name, email, password };
  users.push(user);
  return user;
}

function findUserByEmail(email) {
  return users.find(u => u.email === email);
}

function getAllUsers() {
  return users;
}

module.exports = { createUser, findUserByEmail, getAllUsers };
