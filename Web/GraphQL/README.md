# GraphQL
- GraphQL queries select fields of objects. Each object is of a specific type defined by the backend. The query is structured according to GraphQL syntax, with the name of the query to run at the root. For instance, we can query the id, username, and role fields of all User objects by running the users query:

```graphql
{
  users {
    id
    username
    role
  }
}
```

- GraphQL queries support sub-querying, which enables a query to obtain details from an object referencing another object. For instance, assume that a posts query returns a field author that holds a user object. We can then query the username and role of the author in our query like so:

```graphql
{
  posts {
    title
    author {
      username
      role
    }
  }
}
```

- The result contains the title of all posts as well as the queried data of the corresponding author:

```json
{
  "data": {
    "posts": [
      {
        "title": "Hello World!",
        "author": {
          "username": "htb-stdnt",
          "role": "user"
        }
      },
      {
        "title": "Test",
        "author": {
          "username": "test",
          "role": "user"
        }
      }
    ]
  }
}
```

- [Graphw00f](https://github.com/dolevf/graphw00f) identify the GraphQL engine used by the web application and provides us with the corresponding detailed page in the GraphQL-Threat-Matrix

## Introspection
- Introspection is a GraphQL feature that enables users to query the GraphQL API about the structure of the backend system.

- As such, users can use introspection queries to obtain all queries supported by the API schema. These introspection queries query the `__schema` field.

- For instance, we can identify all GraphQL types supported by the backend using the following query:
```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

- We can obtain all the queries supported by the backend using this query:
```graphql
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}
```

- we can use the following "general" introspection query that dumps all information about types, fields, and queries supported by the backend:
```graphql
query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
```

- We can visualize the schema using the tool [GraphQL-Voyager](https://github.com/graphql-kit/graphql-voyager). Also, we can use [Website](https://graphql-kit.com/graphql-voyager/)