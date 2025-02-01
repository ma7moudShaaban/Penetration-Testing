# GraphQL
- [Introduction](#introduction)
- [Introspection](#introspection)
- [Injection Attacks](#injection-attacks)
- [Denial-of-Service (DoS) & Batching Attacks](#denial-of-service-dos--batching-attacks)
- [Mutations](#mutations)



## Introduction
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

## Injection Attacks

- One of the most common web vulnerabilities are injection attacks such as SQL Injection, Cross-Site Scripting (XSS), and Command Injection. Like all web applications, GraphQL implementations can also suffer from these vulnerabilities.
- To identify if a query requires an argument, we can send the query without any arguments and analyze the response. If the backend expects an argument, the response contains an error that tells us the name of the required argument.

### SQL injection
- To identify if a query requires an argument, we can send the query without any arguments and analyze the response. If the backend expects an argument, the response contains an error that tells us the name of the required argument.

- We can use [GraphQL-Voyager](https://github.com/graphql-kit/graphql-voyager) to identify required arguments

### XSS
- XSS vulnerabilities can occur if GraphQL responses are inserted into the HTML page without proper sanitization.

- XSS vulnerabilities can also occur if invalid arguments are reflected in error messages. Let us look at the post query, which expects an integer ID as an argument. If we instead submit a string argument containing an XSS payload, we can see that the XSS payload is reflected without proper encoding in the GraphQL error message:
[xss](/images/xss.jpg)


## Denial-of-Service (DoS) & Batching Attacks
- Example of DOS:
```graphql
{
  posts {
    author {
      posts {
        edges {
          node {
            author {
              posts {
                edges {
                  node {
                    author {
                      posts {
                        edges {
                          node {
                            author {
                              posts {
                                edges {
                                  node {
                                    author {
                                      posts {
                                        edges {
                                          node {
                                            author {
                                              posts {
                                                edges {
                                                  node {
                                                    author {
                                                      posts {
                                                        edges {
                                                          node {
                                                            author {
                                                              posts {
                                                                edges {
                                                                  node {
                                                                    author {
                                                                      username
                                                                    }
                                                                  }
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

```

- **Batching Attacks**
    - Batching in GraphQL refers to executing multiple queries with a single request. We can do so by directly supplying multiple queries in a JSON list in the HTTP request. For instance, we can query the ID of the user admin and the title of the first post in a single request:
```http
POST /graphql HTTP/1.1
Host: 172.17.0.2
Content-Length: 86
Content-Type: application/json

[
    {
        "query":"{user(username: \"admin\") {uuid}}"
    },
    {
        "query":"{post(id: 1) {title}}"
    }
]
```


## Mutations
- Mutations are GraphQL queries that modify server data. They can be used to create new objects, update existing objects, or delete existing objects.

- Let us start by identifying all mutations supported by the backend and their arguments. We will use the following introspection query:
```graphql
query {
  __schema {
    mutationType {
      name
      fields {
        name
        args {
          name
          defaultValue
          type {
            ...TypeRef
          }
        }
      }
    }
  }
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

