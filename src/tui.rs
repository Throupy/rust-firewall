use std::sync::{Arc, Mutex};

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};

use crossterm::{
    execute,
    terminal::{
        enable_raw_mode, disable_raw_mode,
        EnterAlternateScreen, LeaveAlternateScreen
    },
};

use crate::app::AppState;

pub fn run_tui(app_state: Arc<Mutex<AppState>>) {
    // setup terminal
    enable_raw_mode().unwrap();
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    loop {
        terminal.draw(|f| {
            // layout, split screen into 3 vertical chunks (for now... might change)
            let main_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(70),
                    Constraint::Percentage(30),
                ])
                .split(f.area());
        
            let bottom_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Percentage(50),
                ])
                .split(main_chunks[1]);

            let state = app_state.lock().unwrap();

            // packet log pane
            let items: Vec<ListItem> = state.packets.iter()
                .rev()
                .take(50)
                .map(|p| ListItem::new(p.as_str()))
                .collect();
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Packets"));
            f.render_widget(list, main_chunks[0]);

            // stats pane
            let stats_text = format!(
                "Total Packets Recieved: {}\nTotal Rule Matches: {}", 
                state.total, state.matched,
            );
            let stats_para = Paragraph::new(stats_text)
                .block(Block::default().borders(Borders::ALL).title("Stats"));
            f.render_widget(stats_para, bottom_chunks[0]);

            // help pane
            let help_para = Paragraph::new("q: quit")
                .block(Block::default().borders(Borders::ALL).title("Help"));
            f.render_widget(help_para, bottom_chunks[1]);

        }).unwrap();

        // handle input
        if crossterm::event::poll(std::time::Duration::from_millis(100)).unwrap() {
            if let crossterm::event::Event::Key(key) = crossterm::event::read().unwrap() {
                if key.code == crossterm::event::KeyCode::Char('q') { break; }
            }
        }
    }

    // cleanup terminal
    disable_raw_mode().unwrap();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).unwrap();
}