use std::path::PathBuf;
use whipplescript_store::vcs::NativeWorkspaceVcs;
use whipplescript_store::workstreams::WorkstreamStore;

pub struct Fixture(pub PathBuf);

fn source(case: &str, file: &str) -> &'static str {
    match (case, file) {
        ("fork", "branches.sql") => include_str!("../fixtures/mtarget-v1.0.1/fork/branches.sql"),
        ("fork", "content.sql") => include_str!("../fixtures/mtarget-v1.0.1/fork/content.sql"),
        ("fork", "streams.sql") => include_str!("../fixtures/mtarget-v1.0.1/fork/streams.sql"),
        ("fork", "source-home.json") => {
            include_str!("../fixtures/mtarget-v1.0.1/fork/source-home.json")
        }
        ("fork", "fork.json") => include_str!("../fixtures/mtarget-v1.0.1/fork/fork.json"),
        ("archived", "branches.sql") => {
            include_str!("../fixtures/mtarget-v1.0.1/archived/branches.sql")
        }
        ("archived", "content.sql") => {
            include_str!("../fixtures/mtarget-v1.0.1/archived/content.sql")
        }
        ("archived", "streams.sql") => {
            include_str!("../fixtures/mtarget-v1.0.1/archived/streams.sql")
        }
        ("archived", "boundary.json") => {
            include_str!("../fixtures/mtarget-v1.0.1/archived/boundary.json")
        }
        ("archived", "accepted-ref.json") => {
            include_str!("../fixtures/mtarget-v1.0.1/archived/accepted-ref.json")
        }
        ("landed", "branches.sql") => {
            include_str!("../fixtures/mtarget-v1.0.1/landed/branches.sql")
        }
        ("landed", "content.sql") => include_str!("../fixtures/mtarget-v1.0.1/landed/content.sql"),
        ("landed", "streams.sql") => include_str!("../fixtures/mtarget-v1.0.1/landed/streams.sql"),
        ("landed", "boundary.json") => {
            include_str!("../fixtures/mtarget-v1.0.1/landed/boundary.json")
        }
        ("landed", "accepted-ref.json") => {
            include_str!("../fixtures/mtarget-v1.0.1/landed/accepted-ref.json")
        }
        _ => panic!("unknown legacy receipt fixture {case}/{file}"),
    }
}

pub fn expected(case: &str, file: &str) -> serde_json::Value {
    serde_json::from_str(source(case, file)).expect("valid generated legacy receipt fixture")
}

impl Fixture {
    pub fn load(case: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "whip-receipt-upgrade-{case}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("valid generated legacy receipt fixture")
                .as_nanos()
        ));
        std::fs::create_dir(&root).expect("valid generated legacy receipt fixture");
        for name in ["branches", "content", "streams"] {
            rusqlite::Connection::open(root.join(format!("{name}.sqlite")))
                .expect("valid generated legacy receipt fixture")
                .execute_batch(source(case, &format!("{name}.sql")))
                .expect("valid generated legacy receipt fixture");
        }
        Self(root)
    }

    pub fn open(&self) -> (WorkstreamStore, NativeWorkspaceVcs) {
        (
            WorkstreamStore::open(self.0.join("streams.sqlite"))
                .expect("valid generated legacy receipt fixture"),
            NativeWorkspaceVcs::open(
                self.0.join("branches.sqlite"),
                self.0.join("content.sqlite"),
            )
            .expect("valid generated legacy receipt fixture"),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("valid generated legacy receipt fixture");
    }
}
