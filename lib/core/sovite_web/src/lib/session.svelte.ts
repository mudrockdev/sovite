// The admin token of this browser tab. It is kept in sessionStorage, so
// it is gone when the tab closes, and never sent anywhere but the API.

const key = 'sovite.token';

function stored(): string | null {
	return typeof sessionStorage === 'undefined' ? null : sessionStorage.getItem(key);
}

class Session {
	token = $state<string | null>(stored());

	signIn(token: string) {
		sessionStorage.setItem(key, token);
		this.token = token;
	}

	signOut() {
		sessionStorage.removeItem(key);
		this.token = null;
	}
}

export const session = new Session();
