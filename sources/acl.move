// Copyright (c) Tucana Technology Limited

/// Fork @https://github.com/pentagonxyz/movemate.git
///
/// `acl` is a simple access control module, where `member` represents a member and `role` represents a type
/// of permission. A member can have multiple permissions.
module tucana_std::acl {
    use std::vector;
    use std::option;
    use initia_std::table::{Self, Table};

    const MAX_U128: u128 = 340282366920938463463374607431768211455;

    /// @dev When attempting to add/remove a role >= 128.
    const ERoleNumberTooLarge: u64 = 0;
     const EMemberNotExists: u64 = 1;

    /// @dev Maps addresses to `u128`s with each bit representing the presence of (or lack of) each role.
    struct ACL has key, store {
        permissions: Table<address, u128>
    }

    struct Member has store, drop, copy {
        address: address,
        permission: u128
    }

    /// @notice Create a new ACL (access control list).
    public fun new(): ACL {
        ACL { permissions: table::new() }
    }

    /// @notice Check if a member has a role in the ACL.
    public fun has_role(acl: &ACL, member: address, role: u8): bool {
        assert!(role < 128, ERoleNumberTooLarge);
        table::contains(&acl.permissions, member) && *table::borrow(
            &acl.permissions,
            member
        ) & (1 << role) > 0
    }

    /// @notice Set all roles for a member in the ACL.
    /// @param permissions Permissions for a member, represented as a `u128` with each bit representing the presence of (or lack of) each role.
    public fun set_roles(acl: &mut ACL, member: address, permissions: u128) {
        if (table::contains(&acl.permissions, member)) {
            *table::borrow_mut(&mut acl.permissions, member) = permissions
        } else {
            table::add(&mut acl.permissions, member, permissions);
        }
    }

    /// @notice Add a role for a member in the ACL.
    public fun add_role(acl: &mut ACL, member: address, role: u8) {
        assert!(role < 128, ERoleNumberTooLarge);
        if (table::contains(&acl.permissions, member)) {
            let perms = table::borrow_mut(&mut acl.permissions, member);
            *perms = *perms | (1 << role);
        } else {
            table::add(&mut acl.permissions, member, 1 << role);
        }
    }

    /// @notice Revoke a role for a member in the ACL.
    public fun remove_role(acl: &mut ACL, member: address, role: u8) {
        assert!(role < 128, ERoleNumberTooLarge);
        if (table::contains(&acl.permissions, member)) {
            let perms = table::borrow_mut(&mut acl.permissions, member);
            *perms = *perms & (MAX_U128 - (1 << role));
        }else {
            abort EMemberNotExists

        }
    }

    /// Remove all roles of member.
    public fun remove_member(acl: &mut ACL, member: address) {
        if (table::contains(&acl.permissions, member)) {
            let _ = table::remove(&mut acl.permissions, member);
        }else {
            abort EMemberNotExists
        }
    }

    /// Get all members.
    public fun get_members(acl: &ACL): vector<Member> {
        let members = vector::empty<Member>();
        let iter = table::iter(
            &acl.permissions,
            option::none<address>(),
            option::none<address>(),
            1
        );
        loop {
            if (!table::prepare(&mut iter)) {
                break
            };
            let (address, permission) = table::next(&mut iter);
            vector::push_back(&mut members, Member {
                address,
                permission: *permission
            })
        };
        members
    }

    /// Get the permission of member by addresss.
    public fun get_permission(acl: &ACL, address: address): u128 {
        if (!table::contains(&acl.permissions, address)) {
            0
        } else {
            *table::borrow(&acl.permissions, address)
        }
    }

    #[test(owner = @0x1001)]
    fun test_end_to_end(
        owner: signer
    ) {
        let acl = new();

        add_role(&mut acl, @0x1234, 12);
        add_role(&mut acl, @0x1234, 99);
        add_role(&mut acl, @0x1234, 88);
        add_role(&mut acl, @0x1234, 123);
        add_role(&mut acl, @0x1234, 2);
        add_role(&mut acl, @0x1234, 1);
        remove_role(&mut acl, @0x1234, 2);
        set_roles(&mut acl, @0x5678, (1 << 123) | (1 << 2) | (1 << 1));
        let i = 0;
        while (i < 128) {
            let has = has_role(&acl, @0x1234, i);
            assert!(if (i == 12 || i == 99 || i == 88 || i == 123 || i == 1) has else !has, 0);
            has = has_role(&acl, @0x5678, i);
            assert!(if (i == 123 || i == 2 || i == 1) has else !has, 1);
            i = i + 1;
        };
        move_to(&owner, acl);
    }

    #[test(owner = @0x1001)]
    fun test_add_role_has_role(
        owner: signer
    ) {
        let acl = new();
        assert!(!has_role(&acl, @0x1234, 9), 0);
        add_role(&mut acl, @0x1234, 9);
        assert!(has_role(&acl, @0x1234, 9), 1);
        move_to(&owner, acl)
    }

    #[test(owner = @0x1001)]
    fun test_remove_role(
        owner: signer
    ) {
        let acl = new();
        assert!(!has_role(&acl, @0x1234, 9), 0);
        add_role(&mut acl, @0x1234, 9);
        assert!(has_role(&acl, @0x1234, 9), 1);
        remove_role(&mut acl, @0x1234, 9);
        assert!(!has_role(&acl, @0x1234, 9), 2);
        move_to(&owner, acl)
    }

    #[test(owner = @0x1001)]
    fun test_set_role(
        owner: signer
    ) {
        let acl = new();
        add_role(&mut acl, @0x1234, 10);
        set_roles(&mut acl, @0x1234, 5);
        assert!(!has_role(&acl, @0x1234, 10), 0);
        assert!(has_role(&acl, @0x1234, 0), 1);
        assert!(has_role(&acl, @0x1234, 2), 2);
        assert!(get_permission(&acl, @0x1234) == 5, 3);
        move_to(&owner, acl)
    }

    #[test(owner = @0x1001)]
    fun test_remove_member(
        owner: signer
    ) {
        let acl = new();
        add_role(&mut acl, @0x1234, 10);
        add_role(&mut acl, @0x5678, 10);
        assert!(has_role(&acl, @0x5678, 10), 1);
        remove_role(&mut acl, @0x1234, 10);
        assert!(!has_role(&acl, @0x1234, 10), 2);
        assert!(has_role(&acl, @0x5678, 10), 3);
        move_to(&owner, acl)
    }
}
