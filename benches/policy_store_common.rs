use treetop_core::{
    Action, PolicyEngine, PolicyStoreConfig, PolicyStoreLayout, Principal, Request, Resource, User,
};

pub struct PolicyStoreScenario {
    pub monolithic: PolicyEngine,
    pub scoped: PolicyEngine,
    pub request: Request,
}

pub fn build_policy_store_scenario(
    store_count: usize,
    policies_per_store: usize,
) -> PolicyStoreScenario {
    let mut policy_text = String::new();
    let mut stores = Vec::with_capacity(store_count);
    for store_index in 0..store_count {
        let namespace = format!("Store{store_index}");
        stores.push(
            PolicyStoreConfig::new(format!("store-{store_index}"), &namespace)
                .expect("benchmark store configuration must be valid"),
        );
        for policy_index in 0..policies_per_store {
            policy_text.push_str(&format!(
                "permit (principal == User::\"target\", action == {namespace}::Action::\"read-{policy_index}\", resource is {namespace}::Document);\n"
            ));
        }
    }

    let layout = PolicyStoreLayout::new(stores).expect("benchmark layout must be valid");
    let monolithic =
        PolicyEngine::new_from_str(&policy_text).expect("benchmark policies must compile");
    let scoped = PolicyEngine::new_from_str_with_policy_stores(&policy_text, layout)
        .expect("benchmark policies must partition");
    let request = Request {
        principal: Principal::User(User::new("target", None, None).unwrap()),
        action: Action::new("read-0", Some(vec!["Store0".to_string()])).unwrap(),
        resource: Resource::new("Store0::Document", "document-0").unwrap(),
    };

    PolicyStoreScenario {
        monolithic,
        scoped,
        request,
    }
}
