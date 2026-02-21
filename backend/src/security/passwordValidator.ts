export const validatePassword = (password: string): boolean => {
  const strongRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;

  return strongRegex.test(password);
};