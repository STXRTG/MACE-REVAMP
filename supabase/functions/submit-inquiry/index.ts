import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

async function sha256(message: string): Promise<string> {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

serve(async (req) => {
    if (req.method === 'OPTIONS') {
        return new Response('ok', { headers: corsHeaders })
    }

    try {
        const { name, email, phone, project, proof } = await req.json()

        // 1. Server-side Proof-of-Work Verification
        const DIFFICULTY = 4;
        const prefix = '0'.repeat(DIFFICULTY);

        // Validate age (5 mins max)
        const age = Date.now() - proof.timestamp;
        if (age > 5 * 60 * 1000 || age < 0) {
            throw new Error('Verification expired. Please refresh.')
        }

        // Recalculate hash to verify the work
        const computed = await sha256(`${proof.challenge}:${proof.nonce}`);
        if (computed !== proof.hash || !computed.startsWith(prefix)) {
            throw new Error('Invalid verification. Please try again.')
        }

        // 2. Insert into Database using Service Role (bypassing RLS)
        const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? '';
        const serviceKey = Deno.env.get('SERVICE_ROLE_KEY') ?? '';

        if (!supabaseUrl || !serviceKey) {
            console.error('Missing environment variables. Ensure SUPABASE_URL and SERVICE_ROLE_KEY are set.');
            throw new Error('Server configuration error.');
        }

        const supabaseClient = createClient(supabaseUrl, serviceKey);

        const { error } = await supabaseClient
            .from('inquiries')
            .insert([{ name, email, phone, project, status: 'active' }])

        if (error) {
            console.error('Database insert error:', error);
            throw error;
        }

        console.log('Successfully recorded inquiry from:', email);

        return new Response(JSON.stringify({ message: 'Success' }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            status: 200,
        })

    } catch (error) {
        console.error('Function error:', error.message);
        return new Response(JSON.stringify({ error: error.message }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            status: 400,
        })
    }
})
