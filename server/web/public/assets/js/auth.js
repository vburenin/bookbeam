// Small session helpers shared by settings and pairing. (Signing out is
// accounts.signOutListener: the device may hand over to another listener.)

/** Icon name for a device from its session name ("Tesla", "iPhone · Safari"…). */
export function deviceIcon(name) {
  const n = String(name || '');
  if (/tesla|car/i.test(n)) return 'car';
  if (/iphone|android|ipad|phone/i.test(n)) return 'phone';
  return 'laptop';
}
