package cs492finalproject.Interfaces;

import java.awt.Color;
import javax.swing.JTextPane;

/**
 *
 * @author JBristol
 */
public interface LogInterface {
  public void appendLog(JTextPane log, String message, Color txtColor);
}
