use color_eyre::eyre::eyre;
use cynic::{GraphQlResponse, MutationBuilder};

use super::{
    super::{GitHubError, client::GitHub},
    github_schema as schema,
};

#[derive(cynic::QueryVariables)]
pub struct IgnoreSubscriptionVariables<'a> {
    pub subscribable_id: &'a cynic::Id,
}

/// <https://docs.github.com/graphql/reference/mutations#updatesubscription>
#[derive(cynic::QueryFragment)]
#[cynic(graphql_type = "Mutation", variables = "IgnoreSubscriptionVariables")]
pub struct IgnoreSubscription {
    #[arguments(input: { subscribableId: $subscribable_id, state: IGNORED })]
    pub update_subscription: Option<UpdateSubscriptionPayload>,
}

#[derive(cynic::QueryFragment)]
pub struct UpdateSubscriptionPayload {
    #[allow(dead_code)]
    pub client_mutation_id: Option<String>,
}

impl GitHub {
    /// Stops notifications for the given issue or pull request.
    #[allow(dead_code, reason = "used by the Anthelion library target")]
    pub async fn ignore_subscription(
        &self,
        subscribable_id: &cynic::Id,
    ) -> Result<(), GitHubError> {
        let GraphQlResponse { data, errors } = self
            .run_graphql_with_retry(&IgnoreSubscription::build(IgnoreSubscriptionVariables {
                subscribable_id,
            }))
            .await?;

        data.and_then(|data| data.update_subscription)
            .map(|_| ())
            .ok_or_else(|| {
                GitHubError::graphql_errors(eyre!("failed to ignore subscription"), errors)
            })
    }
}

#[cfg(test)]
mod tests {
    use cynic::{Id, MutationBuilder};
    use indoc::indoc;

    use super::{IgnoreSubscription, IgnoreSubscriptionVariables};

    #[test]
    fn ignore_subscription_output() {
        const IGNORE_SUBSCRIPTION_MUTATION: &str = indoc! {"
            mutation IgnoreSubscription($subscribableId: ID!) {
              updateSubscription(input: {subscribableId: $subscribableId, state: IGNORED}) {
                clientMutationId
              }
            }
        "};

        let id = Id::new("");
        let operation = IgnoreSubscription::build(IgnoreSubscriptionVariables {
            subscribable_id: &id,
        });

        assert_eq!(operation.query, IGNORE_SUBSCRIPTION_MUTATION);
    }
}
