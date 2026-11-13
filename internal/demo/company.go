package demo

import (
	"fmt"
	"strings"

	"github.com/aelasmar01Lab/control-assurance/internal/aws/awstest"
)

// The demo company. Pellwick does not exist: its people, addresses,
// repository and account are made up, and its addresses use a domain
// reserved for examples, which can never resolve.
const (
	Company = "Pellwick"
	Domain  = "pellwick.example"
	// Business is what the company does, in one sentence.
	Business = "Pellwick is a fictional company of 25 people that sells appointment scheduling software to outpatient clinics in the United States and the European Union, with an AI scheduling assistant built on Amazon Bedrock and card payments taken through a payment processor."
)

// Person is one synthetic member of staff.
type Person struct {
	Name  string
	Title string
	Team  string
	// Console marks the people who hold an IAM user in the company's AWS
	// account.
	Console bool
}

// Login is the person's sign-in name: given name, a dot, family name.
func (p Person) Login() string {
	return strings.ToLower(strings.ReplaceAll(p.Name, " ", "."))
}

// Email is the person's address at the reserved example domain.
func (p Person) Email() string { return p.Login() + "@" + Domain }

// People is everyone at Pellwick. Every name is invented.
var People = []Person{
	{"Odalys Brennan", "Chief executive", "Leadership", false},
	{"Tobias Achterberg", "Chief technology officer", "Leadership", true},
	{"Imogen Vasquez", "Head of operations", "Leadership", false},

	{"Kwabena Lindqvist", "Engineering manager", "Engineering", true},
	{"Marisol Trevanion", "Staff engineer", "Engineering", true},
	{"Dmitri Okonjo", "Software engineer", "Engineering", true},
	{"Saoirse Nakagawa", "Software engineer", "Engineering", true},
	{"Henrik Abernathy", "Software engineer", "Engineering", false},
	{"Priyanka Delacroix", "Software engineer", "Engineering", false},
	{"Lorcan Whitfield", "Machine learning engineer", "Engineering", true},
	{"Yusra Halvorsen", "Machine learning engineer", "Engineering", true},
	{"Bastien Mwangi", "Platform engineer", "Engineering", true},
	{"Thandiwe Castellano", "Security and compliance lead", "Engineering", true},

	{"Fenella Ostrowski", "Product manager", "Product", false},
	{"Ravindra Sorensen", "Product designer", "Product", false},

	{"Calista Ferreira", "Head of customer success", "Customer success", false},
	{"Emeka Lindgren", "Implementation specialist", "Customer success", false},
	{"Rosalind Petrovic", "Implementation specialist", "Customer success", false},
	{"Jasper Onwudiwe", "Support specialist", "Customer success", false},
	{"Annika Montrose", "Support specialist, EU", "Customer success", false},

	{"Leopold Ashcroft", "Account executive", "Sales", false},
	{"Zainab Thorsen", "Account executive, EU", "Sales", false},

	{"Cordelia Baptiste", "Finance manager", "Finance and people", false},
	{"Matthias Oyelaran", "People operations", "Finance and people", false},
	{"Ingrid Santoro", "Office and IT administrator", "Finance and people", false},
}

// person returns the member of staff with the given name; the seeded
// records name people this way so a renamed person breaks the build.
func person(name string) Person {
	for _, p := range People {
		if p.Name == name {
			return p
		}
	}
	panic("demo: nobody at " + Company + " is called " + name)
}

// iamUsers are the IAM users of the company's account: one for each person
// with console access, with MFA, and one access key used by deployment.
func iamUsers(recent string) []awstest.User {
	var users []awstest.User
	for _, p := range People {
		if p.Console {
			users = append(users, awstest.User{Name: p.Login(), PasswordEnabled: true, MFA: true, PasswordLastUsed: recent})
		}
	}
	return append(users, awstest.User{Name: "ci-deployer", Key1Active: true, Key1LastUsed: recent, Key1LastRotated: recent})
}

// record is a synthetic document, labelled as one at its head and its foot.
func record(title string, lines ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "SYNTHETIC RECORD\n%s: %s\n\n", Company, title)
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	fmt.Fprintf(&b, "\nThis file is synthetic demo data. %s does not exist.\n", Company)
	return []byte(b.String())
}
