use aya::{
    maps::{MapData, PerCpuArray},
    util::nr_cpus,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table},
    Frame, Terminal,
};
use std::{
    any,
    io::{self, Read, Stdout},
    net::IpAddr,
    str::FromStr,
    time::Duration,
};

use crate::{config::BierMapping, mapping::Mappings};

pub struct RowData {
    pub ipmc_group: String,
    pub packet_count: u64,
    pub bitstring: String,
}

fn truncate_bitstring(bitstring: &str, max_len: usize) -> String {
    if bitstring.len() <= max_len {
        bitstring.to_string()
    } else {
        format!("{}...", &bitstring[..max_len.saturating_sub(3)])
    }
}

pub fn run_tui(mappings: Mappings) -> Result<(), Box<dyn std::error::Error>> {
    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // App state
    let mut selected_index = 0;
    let mut show_popup = false;
    let mut popup_text: String = String::new();

    // Main loop
    loop {
        // Data is updated with every loop iteration
        let data: Vec<RowData> = mappings.get_data();

        terminal.draw(|f| {
            let size = f.area();

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(2)
                .constraints([Constraint::Min(0)].as_ref())
                .split(size);

            draw_table(f, chunks[0], &data, selected_index);

            if show_popup {
                let popup_area = centered_rect(60, 80, size);
                
                // Only capture text on first call
                if popup_text.is_empty() {
                    popup_text = match IpAddr::from_str(&data[selected_index].ipmc_group) {
                    Ok(addr) => {
                        let headers = mappings.get_header_fields(addr);
                        headers.join("\n")
                    }
                    Err(err) => err.to_string(),
                };
                }

                
                draw_popup(f, popup_area, &popup_text);
            } else {
                // Reload content on next popup call
                popup_text.clear();
            }
        })?;

        // Event handling
        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(key) => match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Down => {
                        if selected_index < data.len() - 1 {
                            selected_index += 1;
                        }
                    }
                    KeyCode::Up => {
                        if selected_index > 0 {
                            selected_index -= 1;
                        }
                    }
                    KeyCode::Enter => {
                        show_popup = true;
                    }
                    KeyCode::Esc => {
                        show_popup = false;
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn draw_table(f: &mut Frame, area: Rect, data: &[RowData], selected: usize) {
    let rows: Vec<Row> = data
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let style = if i == selected {
                Style::default().bg(Color::Blue)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(row.ipmc_group.clone()),
                Cell::from(row.packet_count.to_string()),
                Cell::from(truncate_bitstring(&row.bitstring, 256)),
            ])
            .style(style)
        })
        .collect();

    let widths = &[
        Constraint::Percentage(30), // IPMC-Group
        Constraint::Length(15),     // Packet Count
        Constraint::Percentage(55), // Bitstring
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["IPMC-Group", "Packet Count", "Bitstring"])
                .style(Style::default().fg(Color::Yellow)),
        )
        .block(
            Block::default()
                .title("BIER(-TE) Mapper | (q) to quit")
                .borders(Borders::ALL),
        )
        .widths(&[
            Constraint::Percentage(30),
            Constraint::Length(15),
            Constraint::Percentage(55),
        ]);

    f.render_widget(table, area);
}

fn draw_popup(f: &mut Frame, area: Rect, text: &str) {
    let block = Block::default()
        .title("BIER Header | (esc) to close!")
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Black).fg(Color::White));

    let paragraph = Paragraph::new(text).block(block).alignment(Alignment::Left);

    f.render_widget(Clear, area); // Clear underneath
    f.render_widget(paragraph, area);
}

// Helper for centering popups
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}
