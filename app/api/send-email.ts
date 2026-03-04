import { Resend } from 'resend';
import { createClient } from '@supabase/supabase-js';
import type { VercelRequest, VercelResponse } from '@vercel/node';
import { randomUUID, createHash } from 'crypto';

const resend = new Resend(process.env.RESEND_API_KEY || 'missing');
let supabase: any = null;
try {
    if (process.env.VITE_SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
        supabase = createClient(
            process.env.VITE_SUPABASE_URL,
            process.env.SUPABASE_SERVICE_ROLE_KEY
        );
    }
} catch (e) {
    // Graceful degradation
}

function escapeHtml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function sha256(message: string): string {
    return createHash('sha256').update(message).digest('hex');
}

const RATE_WINDOW_SECONDS = 60;
const RATE_MAX = 3;

async function isRateLimited(ip: string): Promise<boolean> {
    if (!supabase) return false;
    const windowStart = new Date(Date.now() - RATE_WINDOW_SECONDS * 1000).toISOString();

    const { count, error } = await supabase
        .from('rate_limits')
        .select('*', { count: 'exact', head: true })
        .eq('ip', ip)
        .gte('created_at', windowStart);

    if (error) {
        return false;
    }

    return (count ?? 0) >= RATE_MAX;
}

async function recordHit(ip: string): Promise<void> {
    if (!supabase) return;
    await supabase.from('rate_limits').insert({ ip });
}

const POW_DIFFICULTY = 4;
const POW_MAX_AGE_MS = 2 * 60 * 1000;

function verifyPoW(pow: { nonce: number; hash: string; challenge: string; timestamp: number }): boolean {
    if (!pow || typeof pow.nonce !== 'number' || typeof pow.hash !== 'string' || typeof pow.challenge !== 'string' || typeof pow.timestamp !== 'number') {
        return false;
    }

    if (Date.now() - pow.timestamp > POW_MAX_AGE_MS) {
        return false;
    }

    const expected = sha256(`${pow.challenge}:${pow.nonce}`);
    if (expected !== pow.hash) {
        return false;
    }

    const prefix = '0'.repeat(POW_DIFFICULTY);
    if (!pow.hash.startsWith(prefix)) {
        return false;
    }

    return true;
}

function isOriginAllowed(req: VercelRequest): boolean {
    const origin = req.headers['origin'] as string | undefined;
    const referer = req.headers['referer'] as string | undefined;

    const checkOrigin = (url: string) => {
        return url.includes('scaming.fans') ||
            url.includes('vercel.app') ||
            url.includes('localhost');
    };

    if (origin && checkOrigin(origin)) return true;
    if (referer && checkOrigin(referer)) return true;

    if (!origin && !referer) return true;

    return false;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
    const requestId = randomUUID();
    res.setHeader('X-Request-ID', requestId);

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    if (!isOriginAllowed(req)) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
        || req.socket?.remoteAddress
        || 'unknown';
    if (await isRateLimited(ip)) {
        return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }

    const { name, email, project, pow } = req.body;

    if (!name || !email || !project) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!verifyPoW(pow)) {
        return res.status(400).json({ error: 'Security verification failed. Please refresh and try again.' });
    }

    const emailStr = String(email).trim().slice(0, 255);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(emailStr)) {
        return res.status(400).json({ error: 'Invalid email address' });
    }

    const safeName = escapeHtml(String(name).slice(0, 100));
    const safeProject = escapeHtml(String(project).slice(0, 5000));

    try {
        await recordHit(ip);

        const { error } = await resend.emails.send({
            from: 'MACE REVAMP <inquiries@scaming.fans>',
            to: [emailStr],
            subject: 'Inquiry Confirmation | MACE REVAMP',
            html: `
<!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inquiry Confirmation</title>
    <!--[if mso]>
    <style type="text/css">
        table {border-collapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;}
        table td {border-collapse:collapse;}
        body, table, td, p, a, span {font-family: Arial, sans-serif !important;}
    </style>
    <![endif]-->
    <style type="text/css">
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=Space+Grotesk:wght@600;700&display=swap');
        body { margin: 0; padding: 0; background-color: #0A0A0A; -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
        table { border-spacing: 0; }
        td { padding: 0; }
        img { border: 0; line-height: 100%; outline: none; text-decoration: none; -ms-interpolation-mode: bicubic; }
        .ExternalClass { width: 100%; }
        .ExternalClass, .ExternalClass p, .ExternalClass span, .ExternalClass font, .ExternalClass td, .ExternalClass div { line-height: 100%; }
        @media screen and (max-width: 600px) {
            .container { width: 100% !important; }
            .content-padding { padding: 30px 20px !important; }
        }
    </style>
</head>
<body style="margin: 0; padding: 0; background-color: #0A0A0A; -webkit-font-smoothing: antialiased;">
    <center style="width: 100%; background-color: #0A0A0A;">
        <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
            <!--[if mso]>
            <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="width:600px;">
            <tr>
            <td align="center" valign="top">
            <![endif]-->
            <table class="container" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; margin: 0 auto; background-color: #141414; border: 1px solid #2A2A2A;">
                <tr>
                    <td class="content-padding" style="padding: 40px; text-align: center;">
                        <p style="margin: 0 0 20px 0; font-family: 'Space Grotesk', Arial, sans-serif; font-size: 16px; font-weight: 700; color: #C68E4E; letter-spacing: 2px; text-transform: uppercase;">
                            MACE REVAMP EB LTD
                        </p>
                        <h1 style="margin: 0 0 20px 0; font-family: 'Space Grotesk', Arial, sans-serif; font-size: 28px; font-weight: 700; color: #FFFFFF;">
                            Inquiry Received
                        </h1>
                        <p style="margin: 0 0 30px 0; font-family: 'Inter', Arial, sans-serif; font-size: 16px; line-height: 24px; color: #F3EFE7; text-align: left;">
                            Hello <strong>${safeName}</strong>,
                            <br><br>
                            Thank you for reaching out. We have received your inquiry and our team is reviewing your project details.
                        </p>
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #0A0A0A; border-left: 3px solid #C68E4E; margin-bottom: 30px;">
                            <tr>
                                <td style="padding: 20px; font-family: 'Inter', Arial, sans-serif; font-size: 14px; line-height: 22px; color: #A0A0A0; text-align: left; font-style: italic;">
                                    "${safeProject}"
                                </td>
                            </tr>
                        </table>
                        <p style="margin: 0 0 30px 0; font-family: 'Inter', Arial, sans-serif; font-size: 16px; line-height: 24px; color: #F3EFE7; text-align: left;">
                            We aim to respond within 1-2 business days with the next steps and an initial estimate.
                        </p>
                        <table border="0" cellpadding="0" cellspacing="0" width="100%">
                            <tr>
                                <td align="center">
                                    <a href="tel:+442079460958" style="display: inline-block; padding: 14px 28px; background-color: #C68E4E; color: #141414; font-family: 'Inter', Arial, sans-serif; font-size: 14px; font-weight: 600; text-decoration: none; text-transform: uppercase; letter-spacing: 1px; border-radius: 4px;">
                                        Call Us Directly
                                    </a>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 20px 40px; background-color: #0A0A0A; text-align: center; border-top: 1px solid #2A2A2A;">
                        <p style="margin: 0; font-family: 'Inter', Arial, sans-serif; font-size: 12px; line-height: 18px; color: #888888; text-transform: uppercase;">
                            &copy; ${new Date().getFullYear()} MACE REVAMP EB LTD. All rights reserved.<br>
                            London &bull; United Kingdom<br>
                            <a href="https://mace-revamp-eb-ltd.vercel.app" style="color: #C68E4E; text-decoration: none;">VISIT PORTFOLIO</a>
                        </p>
                    </td>
                </tr>
            </table>
            <!--[if mso]>
            </td>
            </tr>
            </table>
            <![endif]-->
        </div>
    </center>
</body>
</html>
      `,
        });

        if (error) {
            console.error(`[${requestId}] Email send failed:`, error);
            return res.status(400).json({ error: 'Failed to send email' });
        }

        return res.status(200).json({ success: true });
    } catch (err) {
        console.error(`[${requestId}] Internal error:`, err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}
