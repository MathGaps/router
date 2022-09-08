use anyhow::Result;

mod jwt_auth;

// `cargo run -- -s ../graphql/supergraph.graphql -c ./router.yaml`
fn main() -> Result<()> {
    apollo_router::main()
}
