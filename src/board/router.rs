//! Board HTTP router — uses State<HttpState> with :board_id syntax (axum 0.7)

use crate::board::handlers;
use crate::core::api::types::HttpState;
use crate::core::strategy::RouterHook;
use axum::{routing::{get, post}, Router};

pub struct BoardRouter {
    state: HttpState,
}

impl BoardRouter {
    pub fn new(state: HttpState) -> Self {
        Self { state }
    }
}

impl RouterHook for BoardRouter {
    fn mount(&self, router: Router) -> Router {
        tracing::info!("[a2a_board] BoardRouter mount with State<HttpState>");

        let env_factory = self.state.email_factory.env_factory.clone();

        let board_api = Router::new()
            .route("/api/v1/board/:board_id/task/:task_id", get(handlers::handle_get_task))
            .route("/api/v1/board/:board_id/tasks", get(handlers::handle_list_tasks))
            .route("/api/v1/board/:board_id/members", get(handlers::handle_list_members))
            .route("/api/v1/board/:board_id/status", get(handlers::handle_board_status))
            .route("/api/v1/board/:board_id/roles", get(handlers::handle_list_roles))
            .route("/api/v1/board/:board_id/task/:task_id/heartbeat", post(handlers::handle_post_heartbeat))
            .with_state(self.state.clone());

        router.merge(board_api)
    }
}
