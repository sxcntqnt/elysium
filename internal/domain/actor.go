package domain

// ActorType mirrors the Dgraph ActorType enum and the roles table roles.id column exactly.
// All 24 values must match — never add a mapping layer between the two representations.
type ActorType string

const (
	ActorTypeSuperAdmin        ActorType = "SUPER_ADMIN"
	ActorTypeAdmin             ActorType = "ADMIN"
	ActorTypeOrgChair          ActorType = "ORG_CHAIR"
	ActorTypeGeneralManager    ActorType = "GENERAL_MANAGER"
	ActorTypeFleetManager      ActorType = "FLEET_MANAGER"
	ActorTypeOperationsManager ActorType = "OPERATIONS_MANAGER"
	ActorTypeBranchManager     ActorType = "BRANCH_MANAGER"
	ActorTypeSecretary         ActorType = "SECRETARY"
	ActorTypeAccountant        ActorType = "ACCOUNTANT"
	ActorTypeAccountsClerk     ActorType = "ACCOUNTS_CLERK"
	ActorTypeAuditor           ActorType = "AUDITOR"
	ActorTypeComplianceOfficer ActorType = "COMPLIANCE_OFFICER"
	ActorTypeRouteSupervisor   ActorType = "ROUTE_SUPERVISOR"
	ActorTypeDispatcher        ActorType = "DISPATCHER"
	ActorTypeMechanic          ActorType = "MECHANIC"
	ActorTypeFieldAttendant    ActorType = "FIELD_ATTENDANT"
	ActorTypeDataClerk         ActorType = "DATA_CLERK"
	ActorTypeCustomerSupport   ActorType = "CUSTOMER_SUPPORT"
	ActorTypeSalesManager      ActorType = "SALES_MANAGER"
	ActorTypeOperator          ActorType = "OPERATOR"
	ActorTypeDriver            ActorType = "DRIVER"
	ActorTypeConductor         ActorType = "CONDUCTOR"
	ActorTypePassenger         ActorType = "PASSENGER"
	ActorTypeGuest             ActorType = "GUEST"
)

// orgStaffTypes is the set of actor types served by /org/[orgId]/* routes.
// Mirrors ORG_STAFF_TYPES in context.template.ts — excludes ORG_CHAIR (own
// context), SUPER_ADMIN, ADMIN, and all field actors.
var orgStaffTypes = map[ActorType]bool{
	ActorTypeGeneralManager:    true,
	ActorTypeFleetManager:      true,
	ActorTypeOperationsManager: true,
	ActorTypeBranchManager:     true,
	ActorTypeSecretary:         true,
	ActorTypeAccountant:        true,
	ActorTypeAccountsClerk:     true,
	ActorTypeAuditor:           true,
	ActorTypeComplianceOfficer: true,
	ActorTypeRouteSupervisor:   true,
	ActorTypeDispatcher:        true,
	ActorTypeMechanic:          true,
	ActorTypeFieldAttendant:    true,
	ActorTypeDataClerk:         true,
	ActorTypeCustomerSupport:   true,
	ActorTypeSalesManager:      true,
}

// IsOrgStaff reports whether the actor type is an org staff role.
// Mirrors the ORG_STAFF_TYPES.includes() check in context.template.ts.
func IsOrgStaff(t ActorType) bool { return orgStaffTypes[t] }

// IsValid reports whether the actor type is one of the 24 known values.
func (t ActorType) IsValid() bool {
	switch t {
	case ActorTypeSuperAdmin, ActorTypeAdmin, ActorTypeOrgChair,
		ActorTypeGeneralManager, ActorTypeFleetManager, ActorTypeOperationsManager,
		ActorTypeBranchManager, ActorTypeSecretary, ActorTypeAccountant,
		ActorTypeAccountsClerk, ActorTypeAuditor, ActorTypeComplianceOfficer,
		ActorTypeRouteSupervisor, ActorTypeDispatcher, ActorTypeMechanic,
		ActorTypeFieldAttendant, ActorTypeDataClerk, ActorTypeCustomerSupport,
		ActorTypeSalesManager, ActorTypeOperator, ActorTypeDriver,
		ActorTypeConductor, ActorTypePassenger, ActorTypeGuest:
		return true
	}
	return false
}

// ContextActivationInput carries the full ActiveContext fields that the token
// manager will embed in a context-scoped JWT.
//
// The caller sources these fields from Dgraph's getActiveContext query before
// calling IssueContextToken. The auth service does not query Dgraph directly —
// it signs whatever context Dgraph's authoritative resolver has already produced.
//
// Mirrors the Dgraph ActiveContext type:
//
//	type ActiveContext {
//	  actorId: String!
//	  actorType: ActorType!
//	  permissions: [String!]!           # flattened allow-only action strings
//	  delegatedPermissions: [String!]!
//	  policyGroups: [String!]!
//	  ...
//	}
type ContextActivationInput struct {
	UserID               string
	Nickname             string
	Email                string
	ActorID              string    // the specific actor record ID from Dgraph / actors table
	ActorType            ActorType // must be IsValid() before calling IssueContextToken
	Permissions          []string  // flattened allow-only action strings, from ActiveContext
	DelegatedPermissions []string  // flattened delegated allow-only action strings
	PolicyGroups         []string  // policy group IDs (policyGroupIds on Actor)
}
