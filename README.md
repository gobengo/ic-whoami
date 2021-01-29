# ic-whoami

Who are you, really?

Take a look in the mirror.

## Development

1. Install [dfx](https://sdk.dfinity.org/docs/index.html)
2. `dfx start --background --clean`
3. `dfx deploy`
3. `whoami_assets_canister_id=` + see previous output
4. `open "http://localhost:8000/?canisterId=$whoami_assets_canister_id"`

## Deployment

1. `dfx deploy ic`
