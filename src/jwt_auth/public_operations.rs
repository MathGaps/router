use std::collections::HashSet;

use apollo_parser::ast;

#[derive(Clone, Default)]
pub struct PublicOperationsValidator {
    public_operations: HashSet<String>,
}

impl PublicOperationsValidator {
    pub fn new(supergraph_sdl: String) -> Self {
        let mut public_operations = HashSet::<String>::new();
        let parser = apollo_parser::Parser::new(&supergraph_sdl);
        let ast = parser.parse();

        for def in ast.document().definitions() {
            if let ast::Definition::ObjectTypeDefinition(object_type) = def {
                match object_type.name().map(|n| n.text().to_string()).as_deref() {
                    Some("Query" | "Mutation") => {
                        object_type
                            .fields_definition()
                            .expect("expected > 1 field definition")
                            .field_definitions()
                            .filter(check_field_public)
                            .for_each(|f| {
                                public_operations.insert(
                                    f.name()
                                        .expect("valid schema must have field name")
                                        .text()
                                        .to_string(),
                                );
                            });
                    }
                    _ => continue,
                }
            }
        }
        Self { public_operations }
    }

    pub fn validate(&self, query: String) -> bool {
        let parser = apollo_parser::Parser::new(&query);
        let ast = parser.parse();

        for def in ast.document().definitions() {
            if let ast::Definition::OperationDefinition(op) = def {
                for selection in op
                    .selection_set()
                    .map(|ss| ss.selections().collect::<Vec<_>>())
                    .unwrap_or_default()
                {
                    if let ast::Selection::Field(field) = selection {
                        if !self.public_operations.contains(
                            field
                                .name()
                                .expect("valid query document must have field name")
                                .text()
                                .to_string()
                                .trim(),
                        ) {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }
}

fn check_field_public(field_definition: &ast::FieldDefinition) -> bool {
    field_definition
        .directives()
        .map(|o| {
            o.directives().any(|d| {
                d.name()
                    .map(|n| n.to_string().trim() == "public")
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_public_operations() {
        let got = PublicOperationsValidator::new(
            "
type Query {
    getX(): Int! @public
    getY(): Int! @authenticated
}

type Mutation {
    getZ(): String! @public
}

type Pet @public {
    age: Int!
}"
            .to_string(),
        )
        .public_operations;
        let expect: HashSet<String> = vec!["getX", "getZ"].into_iter().map(String::from).collect();
        assert!(got == expect);
    }

    #[test]
    fn validate() {
        let validator = PublicOperationsValidator::new(
            "
type Query {
    getX(): Int! @public
    getY(): Int! @authenticated
    getZ(): String! @public
}"
            .to_string(),
        );
        assert!(validator.validate(
            "
query {
    getX
}

mutation {
    getZ
}
"
            .to_string()
        ));
    }

    #[test]
    fn validate_fail() {
        let validator = PublicOperationsValidator::new(
            "
type Query {
    getX(): Int! @public
    getY(): Int! @authenticated
    getZ(): String! @public
}"
            .to_string(),
        );
        assert!(!validator.validate(
            "
query {
    getY
}

mutation {
    getZ
}
"
            .to_string()
        ));
    }
}
