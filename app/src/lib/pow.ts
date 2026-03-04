const DIFFICULTY = 4;

async function sha256(message: string): Promise<string> {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export interface ProofOfWork {
    nonce: number;
    hash: string;
    challenge: string;
    timestamp: number;
}

export async function solveChallenge(formData: string): Promise<ProofOfWork> {
    const timestamp = Date.now();
    const challenge = `${formData}:${timestamp}`;
    const prefix = '0'.repeat(DIFFICULTY);

    let nonce = 0;
    let hash = '';

    while (true) {
        hash = await sha256(`${challenge}:${nonce}`);
        if (hash.startsWith(prefix)) {
            return { nonce, hash, challenge, timestamp };
        }
        nonce++;
        if (nonce % 1000 === 0) {
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }
}
