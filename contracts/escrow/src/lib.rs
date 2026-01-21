#![no_std]

use soroban_sdk::{contract, contractevent, contractimpl, contracttype, token, Address, Env, Map, Vec};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Role {
    Backend,
    Maintainer,
}

#[contracttype]
#[derive(Clone)]
pub struct AuthorizedKey {
    pub key: Address,
    pub role: Role,
}

#[contractevent]
#[derive(Clone)]
pub struct FundsReleasedEvent {
    pub contributor: Address,
    pub amount: i128,
}

#[contractevent]
#[derive(Clone)]
pub struct RefundEvent {
    pub recipient: Address,
    pub amount: i128,
}

#[contractevent]
#[derive(Clone)]
pub struct BatchPayoutEvent {
    pub payouts: Vec<(Address, i128)>,
}

#[contract]
pub struct EscrowContract;

#[contractimpl]
impl EscrowContract {
    /// Initialize the contract with admin, token address, and initial authorized keys
    ///
    /// Authorization Flow:
    /// - Admin: Can set authorized keys
    /// - Backend: Can trigger automated payouts (release_funds, batch_payout)
    /// - Maintainer: Can trigger refunds (along with backend)
    /// - Everyone: Read-only access to contract state
    pub fn initialize(env: Env, admin: Address, token_address: Address, backend_key: Address, maintainer_keys: Vec<Address>) {
        admin.require_auth();


        // Store admin
        env.storage().instance().set(&"admin", &admin);

        // Store token address
        env.storage().instance().set(&"token", &token_address);

        // Initialize authorized keys map
        let mut auth_keys = Map::new(&env);

        // Add backend key
        auth_keys.set(backend_key.clone(), Role::Backend);

        // Add maintainer keys
        for key in maintainer_keys.iter() {
            auth_keys.set(key, Role::Maintainer);
        }

        env.storage().instance().set(&"authorized_keys", &auth_keys);

        // Initialize reentrancy guard
        env.storage().instance().set(&"locked", &false);
    }

    /// Check if an address is authorized for a specific role
    pub fn is_authorized(env: Env, address: Address, required_role: Role) -> bool {
        let auth_keys: Map<Address, Role> = env.storage().instance().get(&"authorized_keys").unwrap_or(Map::new(&env));

        if let Some(role) = auth_keys.get(address) {
            match required_role {
                Role::Backend => matches!(role, Role::Backend),
                Role::Maintainer => matches!(role, Role::Backend | Role::Maintainer),
            }
        } else {
            false
        }
    }

    /// Reentrancy guard helper
    fn check_reentrancy(env: &Env) {
        let locked: bool = env.storage().instance().get(&"locked").unwrap_or(false);
        if locked {
            panic!("Reentrancy detected");
        }
        env.storage().instance().set(&"locked", &true);
    }

    /// Release reentrancy guard
    fn release_reentrancy(env: &Env) {
        env.storage().instance().set(&"locked", &false);
    }

    /// Set or update an authorized key (admin only)
    pub fn set_authorized_key(env: Env, admin: Address, key: Address, role: Role) {
        admin.require_auth();

        let stored_admin: Address = env.storage().instance().get(&"admin").unwrap();
        if admin != stored_admin {
            panic!("Unauthorized: only admin can set keys");
        }

        let mut auth_keys: Map<Address, Role> = env.storage().instance().get(&"authorized_keys").unwrap_or(Map::new(&env));
        auth_keys.set(key, role);
        env.storage().instance().set(&"authorized_keys", &auth_keys);
    }

    /// Release funds to a contributor (backend only)
    ///
    /// Security: Only authorized backend can trigger. Validates inputs, prevents reentrancy.
    pub fn release_funds(env: Env, backend: Address, contributor: Address, amount: i128) {
        backend.require_auth();

        if !Self::is_authorized(env.clone(), backend, Role::Backend) {
            panic!("Unauthorized: backend only");
        }

        // Input validation
        if amount <= 0 {
            panic!("Invalid amount: must be positive");
        }

        // Reentrancy protection
        Self::check_reentrancy(&env);

        let token_address: Address = env.storage().instance().get(&"token").unwrap();
        let token = token::TokenClient::new(&env, &token_address);

        // Check contract balance
        let contract_balance = token.balance(&env.current_contract_address());
        if contract_balance < amount {
            Self::release_reentrancy(&env);
            panic!("Insufficient funds in escrow");
        }

        // Transfer tokens
        token.transfer(&env.current_contract_address(), &contributor, &amount);

        // Release guard
        Self::release_reentrancy(&env);

        // Emit event
        FundsReleasedEvent {
            contributor,
            amount,
        }.publish(&env);
    }

    /// Refund funds (maintainer or backend)
    ///
    /// Security: Authorized maintainer or backend can trigger. Validates inputs, prevents reentrancy.
    pub fn refund(env: Env, caller: Address, recipient: Address, amount: i128) {
        caller.require_auth();

        if !Self::is_authorized(env.clone(), caller, Role::Maintainer) {
            panic!("Unauthorized: maintainer or backend only");
        }

        // Input validation
        if amount <= 0 {
            panic!("Invalid amount: must be positive");
        }

        // Reentrancy protection
        Self::check_reentrancy(&env);

        let token_address: Address = env.storage().instance().get(&"token").unwrap();
        let token = token::TokenClient::new(&env, &token_address);

        // Check contract balance
        let contract_balance = token.balance(&env.current_contract_address());
        if contract_balance < amount {
            Self::release_reentrancy(&env);
            panic!("Insufficient funds in escrow");
        }

        // Transfer tokens
        token.transfer(&env.current_contract_address(), &recipient, &amount);

        // Release guard
        Self::release_reentrancy(&env);

        // Emit event
        RefundEvent {
            recipient,
            amount,
        }.publish(&env);
    }

    /// Batch payout to multiple contributors (backend only)
    ///
    /// Security: Only authorized backend can trigger. Validates all inputs, prevents reentrancy.
    pub fn batch_payout(env: Env, backend: Address, payouts: Vec<(Address, i128)>) {
        backend.require_auth();

        if !Self::is_authorized(env.clone(), backend, Role::Backend) {
            panic!("Unauthorized: backend only");
        }

        // Input validation
        if payouts.is_empty() {
            panic!("No payouts specified");
        }

        let mut total_amount = 0i128;
        for (_contributor, amount) in payouts.iter() {
            if amount <= 0 {
                panic!("Invalid amount: must be positive");
            }
            total_amount = total_amount.checked_add(amount).unwrap_or_else(|| panic!("Amount overflow"));
        }

        // Reentrancy protection
        Self::check_reentrancy(&env);

        let token_address: Address = env.storage().instance().get(&"token").unwrap();
        let token = token::TokenClient::new(&env, &token_address);

        // Check contract balance
        let contract_balance = token.balance(&env.current_contract_address());
        if contract_balance < total_amount {
            Self::release_reentrancy(&env);
            panic!("Insufficient funds in escrow");
        }

        // Transfer tokens for each payout
        for (contributor, amount) in payouts.iter() {
            token.transfer(&env.current_contract_address(), &contributor, &amount);
        }

        // Release guard
        Self::release_reentrancy(&env);

        // Emit event
        BatchPayoutEvent {
            payouts,
        }.publish(&env);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, MockAuth, MockAuthInvoke}, Env, IntoVal};

    #[test]
    fn test_authorization() {
        let env = Env::default();
        let contract_id = env.register_contract(None, EscrowContract);
        let client = EscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let token = Address::generate(&env);
        let backend = Address::generate(&env);
        let maintainer = Address::generate(&env);
        let unauthorized = Address::generate(&env);

        let maintainer_keys = Vec::from_array(&env, [maintainer.clone()]);

        // Initialize with mocked auth
        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "initialize",
                args: (admin.clone(), token.clone(), backend.clone(), maintainer_keys.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.initialize(&admin, &token, &backend, &maintainer_keys);

        // Test backend authorization
        assert!(client.is_authorized(&backend, &Role::Backend));
        assert!(!client.is_authorized(&maintainer, &Role::Backend));

        // Test maintainer authorization (should allow backend too)
        assert!(client.is_authorized(&backend, &Role::Maintainer));
        assert!(client.is_authorized(&maintainer, &Role::Maintainer));
        assert!(!client.is_authorized(&unauthorized, &Role::Maintainer));
    }
}