use biscuit_auth::{builder, error::Token, Authorizer, KeyPair, PrivateKey};
use rustler::{Atom, Env, Error, NifTuple, ResourceArc, Term, TermType};
use std::{collections::HashMap, sync::Mutex};

mod atoms {
    rustler::atoms! {
        ok,
        err_internal,
        err_language,

        unknown
    }
}

struct AuthorizerResource {
    pub authorizer: Mutex<Authorizer>,
}

struct BiscuitBuilderResource {
    pub builder: Mutex<builder::BiscuitBuilder>,
}

fn load(env: Env, _: Term) -> bool {
    rustler::resource!(AuthorizerResource, env);
    rustler::resource!(BiscuitBuilderResource, env);
    true
}

#[rustler::nif]
fn keypair_new() -> String {
    let root = KeyPair::new();
    format!("{}", root.private().to_bytes_hex())
}

#[rustler::nif]
fn keypair_to_public(k: String) -> String {
    let p = PrivateKey::from_bytes_hex(&k).unwrap();
    let root = KeyPair::from(&p);
    format!("{}", root.public())
}

#[derive(NifTuple)]
struct ErrorTuple {
    lhs: Atom,
    rhs: String,
}

impl ErrorTuple {
    fn new(lhs: Atom, rhs: Option<String>) -> Self {
        Self {
            lhs,
            rhs: rhs.unwrap_or("".to_string()),
        }
    }
}

fn token_error_to_term(e: &Token) -> ErrorTuple {
    match e {
        Token::InternalError => ErrorTuple::new(atoms::err_internal(), None),
        Token::Language(err) => ErrorTuple::new(atoms::err_language(), Some(format!("{:?}", err))),
        _ => todo!("token_error_to_term: {:?}", e),
    }
}

macro_rules! handle_token_error {
    ($e:expr) => {
        match $e {
            Ok(inner) => inner,
            Err(ref error) => return Err(Error::Term(Box::new(token_error_to_term(error)))),
        }
    };
}

fn convert_terms(
    terms: HashMap<String, rustler::Term>,
) -> Result<HashMap<String, builder::Term>, Error> {
    let mut biscuit_terms: HashMap<String, builder::Term> = HashMap::new();
    for (k, v) in terms {
        let vv: builder::Term;
        match v.get_type() {
            TermType::Integer => {
                vv = builder::Term::Integer(v.decode::<i64>()?);
            }
            TermType::Binary => {
                vv = builder::Term::Str(v.decode::<String>()?);
            }
            _ => {
                return Err(Error::Atom("unknown_type"));
            }
        }
        biscuit_terms.insert(k.clone(), vv);
    }
    Ok(biscuit_terms)
}

#[rustler::nif]
fn create_authority(
    spec: String,
    terms: HashMap<String, rustler::Term>,
) -> Result<ResourceArc<AuthorizerResource>, Error> {
    let mut authorizer = Authorizer::new();
    let biscuit_terms = convert_terms(terms).unwrap();
    handle_token_error!(authorizer.add_code_with_params(spec, biscuit_terms, HashMap::new()));
    Ok(ResourceArc::new(AuthorizerResource {
        authorizer: Mutex::new(authorizer),
    }))
}

#[rustler::nif]
fn builder_new() -> Result<ResourceArc<BiscuitBuilderResource>, Error> {
    let builder = biscuit_auth::Biscuit::builder();
    Ok(ResourceArc::new(BiscuitBuilderResource {
        builder: Mutex::new(builder),
    }))
}

#[rustler::nif]
fn builder_add_block(
    builder: ResourceArc<BiscuitBuilderResource>,
    authority: ResourceArc<AuthorizerResource>,
) -> Result<ResourceArc<BiscuitBuilderResource>, Error> {
    {
        let builder = &mut builder.builder.lock().unwrap();
        let block = authority.authorizer.lock().unwrap();
        let (facts, rules, checks, _policies) = block.dump();
        let block_builder = biscuit_auth::builder::BlockBuilder {
            facts: facts.clone(),
            rules: rules.clone(),
            checks: checks.clone(),
            scopes: vec![], // TODO
            context: None,
        };
        builder.merge(block_builder);
    }
    Ok(builder)
}

#[rustler::nif]
fn builder_build(
    builder: ResourceArc<BiscuitBuilderResource>,
    private: String,
) -> Result<String, Error> {
    let builder = builder.builder.lock().unwrap().clone();
    let prive = PrivateKey::from_bytes_hex(&private).unwrap();
    let r = builder.build(&KeyPair::from(&prive));
    let biscuit = handle_token_error!(r);
    Ok(handle_token_error!(biscuit.to_base64()))
}

rustler::init!(
    "Elixir.Biscuit",
    [
        keypair_new,
        keypair_to_public,
        create_authority,
        builder_new,
        builder_add_block,
        builder_build
    ],
    load = load
);
