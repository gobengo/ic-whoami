export const whoami = process.env.CANISTER_ID_whoami || '';

if ( ! whoami) {
    throw new Error('failed to determine CANISTER_ID_whoami')
}
